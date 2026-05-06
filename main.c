#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>   // usleep
#include <arpa/inet.h>
#include <sys/socket.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/accesscontrol_default.h>

#include "model_ids.h"
#include "modbus_collectors.h"

static volatile UA_Boolean running = true;
static UA_UInt16 nsIdx = 0;

#define ENABLE_DISCOVERY_NONE 1
#define SERVER_APP_URI "urn:dataprotect:opcua:ot-server"
#define SERVER_NAME    "Serveur OPC UA PowerGrid"
#define SERVER_PORT    4840

#define SYSLOG_DEFAULT_SERVER "192.168.1.70"
#define SYSLOG_DEFAULT_PORT   514
#define SYSLOG_APP_NAME       "powergrid_opcua_server"
#define SYSLOG_HOSTNAME       "powergrid-opcua"

static int g_syslog_fd = -1;
static struct sockaddr_in g_syslog_addr;
static UA_Boolean g_syslog_enabled = true;

static void ot_syslog_init(void) {
    const char *enabled = getenv("OPCUA_SYSLOG_ENABLED");
    if(enabled && (strcmp(enabled, "false") == 0 || strcmp(enabled, "0") == 0)) {
        g_syslog_enabled = false;
        return;
    }

    const char *server = getenv("SYSLOG_SERVER");
    const char *portStr = getenv("SYSLOG_PORT");
    if(!server || strlen(server) == 0)
        server = SYSLOG_DEFAULT_SERVER;

    int port = portStr ? atoi(portStr) : SYSLOG_DEFAULT_PORT;

    g_syslog_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(g_syslog_fd < 0) {
        g_syslog_enabled = false;
        return;
    }

    memset(&g_syslog_addr, 0, sizeof(g_syslog_addr));
    g_syslog_addr.sin_family = AF_INET;
    g_syslog_addr.sin_port = htons((uint16_t)port);

    if(inet_pton(AF_INET, server, &g_syslog_addr.sin_addr) != 1) {
        close(g_syslog_fd);
        g_syslog_fd = -1;
        g_syslog_enabled = false;
        return;
    }
}

static void ot_syslog_close(void) {
    if(g_syslog_fd >= 0) {
        close(g_syslog_fd);
        g_syslog_fd = -1;
    }
}

static void ot_log_send_both(int severity, const char *fmt, ...) {
    char msg[768];

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    switch(severity) {
        case 2:
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "%s", msg);
            break;
        case 3:
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "%s", msg);
            break;
        case 4:
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "%s", msg);
            break;
        default:
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "%s", msg);
            break;
    }

    if(!g_syslog_enabled || g_syslog_fd < 0)
        return;

    char ts[64];
    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

    int pri = 16 * 8 + severity;

    char packet[1024];
    snprintf(packet, sizeof(packet),
             "<%d>1 %s %s %s - - - [OPCUA] %s",
             pri, ts, SYSLOG_HOSTNAME, SYSLOG_APP_NAME, msg);

    sendto(g_syslog_fd,
           packet,
           strlen(packet),
           0,
           (struct sockaddr*)&g_syslog_addr,
           sizeof(g_syslog_addr));
}

#define LOG_INFO(...)    ot_log_send_both(6, __VA_ARGS__)
#define LOG_WARN(...)    ot_log_send_both(4, __VA_ARGS__)
#define LOG_ERROR(...)   ot_log_send_both(3, __VA_ARGS__)
#define LOG_FATAL(...)   ot_log_send_both(2, __VA_ARGS__)

/* =========================================================
 * ROLES / SESSION CONTEXT
 * ========================================================= */

typedef enum {
    ROLE_NONE      = 0,
    ROLE_ADMIN     = 1 << 0,
    ROLE_SCADA     = 1 << 1,
    ROLE_HISTORIAN = 1 << 2
} RoleMask;

typedef struct UserSessionContext {
    char username[64];
    unsigned int roles;
} UserSessionContext;

/* =========================================================
 * COMMAND MODE
 * ========================================================= */

typedef enum {
    CMD_MODE_MAINTAINED = 0,
    CMD_MODE_PULSE      = 1
} CommandMode;

/* =========================================================
 * COMMAND NODE CONTEXT
 * ========================================================= */

typedef struct CommandNodeContext {
    UA_NodeId nodeId;
    char browseName[64];
    char displayName[64];
    UA_Boolean currentValue;
    unsigned int allowedRoles;
    CommandMode mode;
    struct CommandNodeContext *next;
} CommandNodeContext;

static CommandNodeContext *g_commandNodes = NULL;

/* =========================================================
 * HELPERS
 * ========================================================= */

static const char *statusNameSafe(UA_StatusCode code) {
    const char *name = UA_StatusCode_name(code);
    return name ? name : "UnknownStatus";
}

static UA_NodeId nid(UA_UInt32 id) {
    return UA_NODEID_NUMERIC(nsIdx, id);
}

static const char *rolesToString(unsigned int roles) {
    static char buf[64];
    buf[0] = '\0';

    if(roles == ROLE_NONE) {
        snprintf(buf, sizeof(buf), "ROLE_NONE");
        return buf;
    }

    int first = 1;
    if(roles & ROLE_ADMIN) {
        strncat(buf, "ADMIN", sizeof(buf) - strlen(buf) - 1);
        first = 0;
    }
    if(roles & ROLE_SCADA) {
        if(!first) strncat(buf, "|", sizeof(buf) - strlen(buf) - 1);
        strncat(buf, "SCADA", sizeof(buf) - strlen(buf) - 1);
        first = 0;
    }
    if(roles & ROLE_HISTORIAN) {
        if(!first) strncat(buf, "|", sizeof(buf) - strlen(buf) - 1);
        strncat(buf, "HISTORIAN", sizeof(buf) - strlen(buf) - 1);
    }

    return buf;
}

static const char *modeToString(CommandMode mode) {
    switch(mode) {
        case CMD_MODE_MAINTAINED: return "MAINTAINED";
        case CMD_MODE_PULSE:      return "PULSE";
        default:                  return "UNKNOWN";
    }
}

static unsigned int rolesForUsername(const char *username) {
    if(!username)
        return ROLE_NONE;

    if(strcmp(username, "admin") == 0)
        return ROLE_ADMIN | ROLE_SCADA | ROLE_HISTORIAN;

    if(strcmp(username, "scada") == 0)
        return ROLE_SCADA;

    if(strcmp(username, "historian") == 0)
        return ROLE_HISTORIAN;

    return ROLE_NONE;
}

static const char *safeUsernameFromSession(void *sessionContext) {
    UserSessionContext *ctx = (UserSessionContext*)sessionContext;
    if(!ctx || ctx->username[0] == '\0')
        return "unknown";
    return ctx->username;
}

static UA_Boolean isWriteAuthorized(void *sessionContext,
                                    const CommandNodeContext *nodeCtx) {
    UserSessionContext *userCtx = (UserSessionContext*)sessionContext;
    if(!userCtx || !nodeCtx)
        return false;

    return (userCtx->roles & nodeCtx->allowedRoles) != 0;
}

static void stopHandler(int sig) {
    LOG_INFO("[LIFECYCLE] Signal reçu: %d -> arrêt demandé", sig);
    running = false;
}

static UA_ByteString loadFile(const char *const path) {
    UA_ByteString fileContents = UA_BYTESTRING_NULL;
    FILE *fp = fopen(path, "rb");
    if(!fp) {
        LOG_ERROR("[FILE] Impossible d'ouvrir le fichier: %s", path);
        return fileContents;
    }

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    rewind(fp);

    if(fileSize < 0) {
        LOG_ERROR("[FILE] Taille invalide pour le fichier: %s", path);
        fclose(fp);
        return fileContents;
    }

    fileContents.length = (size_t)fileSize;
    fileContents.data = (UA_Byte *)UA_malloc(fileContents.length);
    if(!fileContents.data) {
        LOG_ERROR("[FILE] Allocation mémoire échouée pour: %s", path);
        fileContents.length = 0;
        fclose(fp);
        return fileContents;
    }

    if(fread(fileContents.data, 1, fileContents.length, fp) != fileContents.length) {
        LOG_ERROR("[FILE] Lecture incomplète du fichier: %s", path);
        UA_ByteString_clear(&fileContents);
        fclose(fp);
        return UA_BYTESTRING_NULL;
    }

    fclose(fp);
    LOG_INFO("[FILE] Chargement OK: %s (%lu bytes)", path, (unsigned long)fileContents.length);
    return fileContents;
}

static void freeCommandContexts(void) {
    CommandNodeContext *cur = g_commandNodes;
    size_t count = 0;

    while(cur) {
        CommandNodeContext *next = cur->next;
        UA_free(cur);
        cur = next;
        count++;
    }

    g_commandNodes = NULL;
    LOG_INFO("[CLEANUP] %lu contextes de commande libérés", (unsigned long)count);
}

static CommandNodeContext *allocateCommandContext(UA_UInt32 id,
                                                  const char *browse,
                                                  const char *display,
                                                  UA_Boolean initialValue,
                                                  unsigned int allowedRoles,
                                                  CommandMode mode) {
    CommandNodeContext *ctx = (CommandNodeContext*)UA_calloc(1, sizeof(CommandNodeContext));
    if(!ctx)
        return NULL;

    ctx->nodeId = nid(id);
    ctx->currentValue = initialValue;
    ctx->allowedRoles = allowedRoles;
    ctx->mode = mode;

    if(browse)
        snprintf(ctx->browseName, sizeof(ctx->browseName), "%s", browse);
    if(display)
        snprintf(ctx->displayName, sizeof(ctx->displayName), "%s", display);

    ctx->next = g_commandNodes;
    g_commandNodes = ctx;

    LOG_INFO("[NODECTX][ALLOC] NodeId=ns=%u;i=%u Browse=%s Display=%s Initial=%s AllowedRoles=%s Mode=%s",
             (unsigned)ctx->nodeId.namespaceIndex,
             (unsigned)ctx->nodeId.identifier.numeric,
             ctx->browseName,
             ctx->displayName,
             initialValue ? "true" : "false",
             rolesToString(ctx->allowedRoles),
             modeToString(ctx->mode));

    return ctx;
}

static void logWriteAttempt(const char *phase,
                            const UA_NodeId *nodeId,
                            const CommandNodeContext *ctx,
                            const char *username,
                            UA_Boolean attemptedValue,
                            UA_StatusCode result) {
    LOG_INFO("[AUDIT][%s] User=%s NodeId=ns=%u;i=%u Browse=%s Display=%s Attempted=%s AllowedRoles=%s Mode=%s Result=%s",
             phase,
             username ? username : "unknown",
             (unsigned)nodeId->namespaceIndex,
             (unsigned)nodeId->identifier.numeric,
             ctx ? ctx->browseName : "(null)",
             ctx ? ctx->displayName : "(null)",
             attemptedValue ? "true" : "false",
             ctx ? rolesToString(ctx->allowedRoles) : "(null)",
             ctx ? modeToString(ctx->mode) : "(null)",
             statusNameSafe(result));
}

/* =========================================================
 * SESSION CALLBACKS
 * ========================================================= */

static UA_StatusCode onActivateSession(UA_Server *server,
                                       UA_AccessControl *ac,
                                       const UA_EndpointDescription *endpoint,
                                       const UA_ByteString *secureChannelRemoteCertificate,
                                       const UA_NodeId *sessionId,
                                       const UA_ExtensionObject *userIdentityToken,
                                       void **sessionContext) {
    (void)server;
    (void)ac;
    (void)endpoint;
    (void)secureChannelRemoteCertificate;

    UserSessionContext *ctx = (UserSessionContext*)UA_calloc(1, sizeof(UserSessionContext));
    if(!ctx) {
        LOG_ERROR("[SESSION][ACTIVATE] Allocation mémoire échouée");
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    if(userIdentityToken &&
       userIdentityToken->content.decoded.type == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN] &&
       userIdentityToken->content.decoded.data) {

        UA_UserNameIdentityToken *tok =
            (UA_UserNameIdentityToken*)userIdentityToken->content.decoded.data;

        size_t len = tok->userName.length;
        if(len >= sizeof(ctx->username))
            len = sizeof(ctx->username) - 1;

        memcpy(ctx->username, tok->userName.data, len);
        ctx->username[len] = '\0';
        ctx->roles = rolesForUsername(ctx->username);

        LOG_INFO("[SESSION][ACTIVATE] SessionId=ns=%u;i=%u User=%s Roles=%s",
                 (unsigned)sessionId->namespaceIndex,
                 (unsigned)sessionId->identifier.numeric,
                 ctx->username,
                 rolesToString(ctx->roles));
    } else {
        snprintf(ctx->username, sizeof(ctx->username), "unknown");
        ctx->roles = ROLE_NONE;

        LOG_WARN("[SESSION][ACTIVATE] Session sans UsernameIdentityToken valide -> User=%s Roles=%s",
                 ctx->username,
                 rolesToString(ctx->roles));
    }

    *sessionContext = ctx;
    return UA_STATUSCODE_GOOD;
}

static void onCloseSession(UA_Server *server,
                           UA_AccessControl *ac,
                           const UA_NodeId *sessionId,
                           void *sessionContext) {
    (void)server;
    (void)ac;

    UserSessionContext *ctx = (UserSessionContext*)sessionContext;
    LOG_INFO("[SESSION][CLOSE] SessionId=ns=%u;i=%u User=%s Roles=%s",
             (unsigned)sessionId->namespaceIndex,
             (unsigned)sessionId->identifier.numeric,
             ctx ? ctx->username : "unknown",
             ctx ? rolesToString(ctx->roles) : "ROLE_NONE");

    if(sessionContext)
        UA_free(sessionContext);
}

/* =========================================================
 * SYNCHRONISATION DES COMMANDES (DEPUIS MODBUS)
 * ========================================================= */

void mettre_a_jour_etat_commande(UA_UInt32 id, UA_Boolean value) {
    CommandNodeContext *cur = g_commandNodes;
    while(cur) {
        if(cur->nodeId.identifierType == UA_NODEIDTYPE_NUMERIC &&
           cur->nodeId.identifier.numeric == id) {
            cur->currentValue = value;
            LOG_INFO("[SYNC][CMD] NodeId=ns=%u;i=%u Browse=%s Mode=%s <- %s",
                     (unsigned)cur->nodeId.namespaceIndex,
                     (unsigned)cur->nodeId.identifier.numeric,
                     cur->browseName,
                     modeToString(cur->mode),
                     value ? "true" : "false");
            return;
        }
        cur = cur->next;
    }

    LOG_WARN("[SYNC][CMD] Aucun contexte trouvé pour id=%u", (unsigned)id);
}

/* =========================================================
 * CALLBACKS
 * ========================================================= */

static UA_StatusCode commandReadCallback(UA_Server *server,
                                         const UA_NodeId *sessionId,
                                         void *sessionContext,
                                         const UA_NodeId *nodeId,
                                         void *nodeContext,
                                         UA_Boolean includeSourceTimeStamp,
                                         const UA_NumericRange *range,
                                         UA_DataValue *value) {
    (void)server;
    (void)sessionId;
    (void)range;

    CommandNodeContext *ctx = (CommandNodeContext*)nodeContext;
    if(!ctx) {
        LOG_ERROR("[READ][CMD] nodeContext nul");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_DataValue_init(value);
    UA_Variant_setScalarCopy(&value->value, &ctx->currentValue, &UA_TYPES[UA_TYPES_BOOLEAN]);
    value->hasValue = true;
    value->status = UA_STATUSCODE_GOOD;
    value->hasStatus = true;

    if(includeSourceTimeStamp) {
        value->sourceTimestamp = UA_DateTime_now();
        value->hasSourceTimestamp = true;
    }

    LOG_INFO("[READ][CMD] User=%s NodeId=ns=%u;i=%u Browse=%s Display=%s Mode=%s Value=%s",
             safeUsernameFromSession(sessionContext),
             (unsigned)nodeId->namespaceIndex,
             (unsigned)nodeId->identifier.numeric,
             ctx->browseName,
             ctx->displayName,
             modeToString(ctx->mode),
             ctx->currentValue ? "true" : "false");

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode commandWriteMaintained(const UA_NodeId *nodeId,
                                            CommandNodeContext *ctx,
                                            const char *username,
                                            UA_Boolean requestedValue) {
    int writeRc = ecrire_commande_modbus(nodeId->identifier.numeric, requestedValue);

    if(writeRc == 0) {
        LOG_ERROR("[WRITE][CMD][MAINTAINED][MODBUS-ERR] User=%s NodeId=ns=%u;i=%u Requested=%s",
                  username,
                  (unsigned)nodeId->namespaceIndex,
                  (unsigned)nodeId->identifier.numeric,
                  requestedValue ? "true" : "false");

        logWriteAttempt("DENY", nodeId, ctx, username, requestedValue, UA_STATUSCODE_BADCOMMUNICATIONERROR);
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }

    if(writeRc < 0) {
        LOG_WARN("[WRITE][CMD][MAINTAINED][LOCAL] User=%s NodeId=ns=%u;i=%u non mappé Modbus, shadow local uniquement",
                 username,
                 (unsigned)nodeId->namespaceIndex,
                 (unsigned)nodeId->identifier.numeric);
    } else {
        LOG_INFO("[WRITE][CMD][MAINTAINED] User=%s NodeId=ns=%u;i=%u Coil fixée à %s",
                 username,
                 (unsigned)nodeId->namespaceIndex,
                 (unsigned)nodeId->identifier.numeric,
                 requestedValue ? "true" : "false");
    }

    ctx->currentValue = requestedValue;

    logWriteAttempt("ACCEPT", nodeId, ctx, username, requestedValue, UA_STATUSCODE_GOOD);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode commandWritePulse(const UA_NodeId *nodeId,
                                       CommandNodeContext *ctx,
                                       const char *username,
                                       UA_Boolean requestedValue) {
    /* Preserve old behavior for pulse nodes only */
    int writeRc = ecrire_commande_modbus(nodeId->identifier.numeric, requestedValue);
    if(writeRc == 0) {
        LOG_ERROR("[WRITE][CMD][PULSE][MODBUS-ERR] User=%s NodeId=ns=%u;i=%u phase=INITIAL_WRITE Requested=%s",
                  username,
                  (unsigned)nodeId->namespaceIndex,
                  (unsigned)nodeId->identifier.numeric,
                  requestedValue ? "true" : "false");

        logWriteAttempt("DENY", nodeId, ctx, username, requestedValue, UA_STATUSCODE_BADCOMMUNICATIONERROR);
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }

    if(writeRc < 0) {
        LOG_WARN("[WRITE][CMD][PULSE][LOCAL] User=%s NodeId=ns=%u;i=%u non mappé Modbus, shadow local/pulse logique",
                 username,
                 (unsigned)nodeId->namespaceIndex,
                 (unsigned)nodeId->identifier.numeric);
    }

    /* Only trigger on TRUE */
    if(requestedValue == true) {
        LOG_INFO("[WRITE][CMD][PULSE] User=%s NodeId=ns=%u;i=%u -> second TRUE write",
                 username,
                 (unsigned)nodeId->namespaceIndex,
                 (unsigned)nodeId->identifier.numeric);

        int rc1 = ecrire_commande_modbus(nodeId->identifier.numeric, true);

        if(rc1 == 0) {
            LOG_ERROR("[WRITE][CMD][PULSE][MODBUS-ERR] User=%s NodeId=ns=%u;i=%u phase=SECOND_TRUE",
                      username,
                      (unsigned)nodeId->namespaceIndex,
                      (unsigned)nodeId->identifier.numeric);

            logWriteAttempt("DENY", nodeId, ctx, username, requestedValue, UA_STATUSCODE_BADCOMMUNICATIONERROR);
            return UA_STATUSCODE_BADCOMMUNICATIONERROR;
        }

        usleep(100 * 1000);

        LOG_INFO("[WRITE][CMD][PULSE][RESET] User=%s NodeId=ns=%u;i=%u -> reset FALSE",
                 username,
                 (unsigned)nodeId->namespaceIndex,
                 (unsigned)nodeId->identifier.numeric);

        ecrire_commande_modbus(nodeId->identifier.numeric, false);

        ctx->currentValue = false;

        LOG_INFO("[WRITE][CMD][PULSE][SUCCESS] User=%s NodeId=ns=%u;i=%u pulse exécutée, état OPC UA=false",
                 username,
                 (unsigned)nodeId->namespaceIndex,
                 (unsigned)nodeId->identifier.numeric);

        logWriteAttempt("ACCEPT", nodeId, ctx, username, requestedValue, UA_STATUSCODE_GOOD);
        return UA_STATUSCODE_GOOD;
    }

    ctx->currentValue = false;

    LOG_INFO("[WRITE][CMD][PULSE][FALSE-IGNORED] User=%s NodeId=ns=%u;i=%u FALSE reçu, pas d'action supplémentaire",
             username,
             (unsigned)nodeId->namespaceIndex,
             (unsigned)nodeId->identifier.numeric);

    logWriteAttempt("ACCEPT", nodeId, ctx, username, requestedValue, UA_STATUSCODE_GOOD);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode commandWriteCallback(UA_Server *server,
                                          const UA_NodeId *sessionId,
                                          void *sessionContext,
                                          const UA_NodeId *nodeId,
                                          void *nodeContext,
                                          const UA_NumericRange *range,
                                          const UA_DataValue *value) {
    (void)server;
    (void)sessionId;
    (void)range;

    CommandNodeContext *ctx = (CommandNodeContext*)nodeContext;
    const char *username = safeUsernameFromSession(sessionContext);

    if(!ctx) {
        LOG_ERROR("[WRITE][CMD] nodeContext nul");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    LOG_INFO("[WRITE][CMD][START] User=%s NodeId=ns=%u;i=%u Browse=%s Display=%s Mode=%s",
             username,
             (unsigned)nodeId->namespaceIndex,
             (unsigned)nodeId->identifier.numeric,
             ctx->browseName,
             ctx->displayName,
             modeToString(ctx->mode));

    if(!value || !value->hasValue) {
        logWriteAttempt("DENY", nodeId, ctx, username, false, UA_STATUSCODE_BADNODATAAVAILABLE);
        return UA_STATUSCODE_BADNODATAAVAILABLE;
    }

    if(!UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_BOOLEAN])) {
        logWriteAttempt("DENY", nodeId, ctx, username, false, UA_STATUSCODE_BADTYPEMISMATCH);
        return UA_STATUSCODE_BADTYPEMISMATCH;
    }

    if(!value->value.data) {
        logWriteAttempt("DENY", nodeId, ctx, username, false, UA_STATUSCODE_BADNODATAAVAILABLE);
        return UA_STATUSCODE_BADNODATAAVAILABLE;
    }

    if(nodeId->identifierType != UA_NODEIDTYPE_NUMERIC) {
        logWriteAttempt("DENY", nodeId, ctx, username, false, UA_STATUSCODE_BADNODEIDINVALID);
        return UA_STATUSCODE_BADNODEIDINVALID;
    }

    UA_Boolean requestedValue = *(UA_Boolean*)value->value.data;

    LOG_INFO("[WRITE][CMD][REQUEST] User=%s NodeId=ns=%u;i=%u Requested=%s AllowedRoles=%s Mode=%s",
             username,
             (unsigned)nodeId->namespaceIndex,
             (unsigned)nodeId->identifier.numeric,
             requestedValue ? "true" : "false",
             rolesToString(ctx->allowedRoles),
             modeToString(ctx->mode));

    if(!isWriteAuthorized(sessionContext, ctx)) {
        LOG_WARN("[WRITE][CMD][AUTHZ-DENY] User=%s NodeId=ns=%u;i=%u Browse=%s Display=%s RequiredRoles=%s",
                 username,
                 (unsigned)nodeId->namespaceIndex,
                 (unsigned)nodeId->identifier.numeric,
                 ctx->browseName,
                 ctx->displayName,
                 rolesToString(ctx->allowedRoles));

        logWriteAttempt("DENY", nodeId, ctx, username, requestedValue, UA_STATUSCODE_BADUSERACCESSDENIED);
        return UA_STATUSCODE_BADUSERACCESSDENIED;
    }

    if(ctx->mode == CMD_MODE_MAINTAINED)
        return commandWriteMaintained(nodeId, ctx, username, requestedValue);

    return commandWritePulse(nodeId, ctx, username, requestedValue);
}

/* =========================================================
 * NODE BUILDERS
 * ========================================================= */

static UA_NodeId addObject(UA_Server *server, UA_NodeId parent,
                           UA_UInt32 id,
                           const char *browse,
                           const char *display) {
    UA_ObjectAttributes attr = UA_ObjectAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("fr-FR", (char*)display);

    UA_NodeId newId = nid(id);
    UA_QualifiedName qn = UA_QUALIFIEDNAME(nsIdx, (char*)browse);

    UA_NodeId out = UA_NODEID_NULL;
    UA_StatusCode rc = UA_Server_addObjectNode(server, newId, parent,
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
        qn,
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
        attr, NULL, &out);

    if(rc == UA_STATUSCODE_GOOD) {
        LOG_INFO("[BUILD][OBJECT] OK Parent=ns=%u;i=%u NodeId=ns=%u;i=%u Browse=%s Display=%s",
                 (unsigned)parent.namespaceIndex,
                 (unsigned)(parent.identifierType == UA_NODEIDTYPE_NUMERIC ? parent.identifier.numeric : 0),
                 (unsigned)out.namespaceIndex,
                 (unsigned)(out.identifierType == UA_NODEIDTYPE_NUMERIC ? out.identifier.numeric : 0),
                 browse, display);
    } else {
        LOG_ERROR("[BUILD][OBJECT] FAIL Browse=%s Display=%s Result=%s",
                  browse, display, statusNameSafe(rc));
    }

    return out;
}

static void addTelemetryBool(UA_Server *server, UA_NodeId parent,
                             UA_UInt32 id,
                             const char *browse,
                             const char *display,
                             UA_Boolean value) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Variant_setScalar(&attr.value, &value, &UA_TYPES[UA_TYPES_BOOLEAN]);
    attr.displayName = UA_LOCALIZEDTEXT("fr-FR", (char*)display);
    attr.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ;
    attr.userAccessLevel = UA_ACCESSLEVELMASK_READ;

    UA_StatusCode rc = UA_Server_addVariableNode(server,
        nid(id),
        parent,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(nsIdx, (char*)browse),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        attr,
        NULL,
        NULL);

    if(rc == UA_STATUSCODE_GOOD) {
        LOG_INFO("[BUILD][TEL-BOOL] OK Parent=ns=%u;i=%u NodeId=ns=%u;i=%u Browse=%s Display=%s Initial=%s",
                 (unsigned)parent.namespaceIndex,
                 (unsigned)(parent.identifierType == UA_NODEIDTYPE_NUMERIC ? parent.identifier.numeric : 0),
                 (unsigned)nsIdx,
                 (unsigned)id,
                 browse,
                 display,
                 value ? "true" : "false");
    } else {
        LOG_ERROR("[BUILD][TEL-BOOL] FAIL NodeId=ns=%u;i=%u Browse=%s Display=%s Result=%s",
                  (unsigned)nsIdx,
                  (unsigned)id,
                  browse,
                  display,
                  statusNameSafe(rc));
    }
}

static void addTelemetryDouble(UA_Server *server, UA_NodeId parent,
                               UA_UInt32 id,
                               const char *browse,
                               const char *display,
                               UA_Double value) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Variant_setScalar(&attr.value, &value, &UA_TYPES[UA_TYPES_DOUBLE]);
    attr.displayName = UA_LOCALIZEDTEXT("fr-FR", (char*)display);
    attr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ;
    attr.userAccessLevel = UA_ACCESSLEVELMASK_READ;

    UA_StatusCode rc = UA_Server_addVariableNode(server,
        nid(id),
        parent,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(nsIdx, (char*)browse),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        attr,
        NULL,
        NULL);

    if(rc == UA_STATUSCODE_GOOD) {
        LOG_INFO("[BUILD][TEL-DOUBLE] OK Parent=ns=%u;i=%u NodeId=ns=%u;i=%u Browse=%s Display=%s Initial=%f",
                 (unsigned)parent.namespaceIndex,
                 (unsigned)(parent.identifierType == UA_NODEIDTYPE_NUMERIC ? parent.identifier.numeric : 0),
                 (unsigned)nsIdx,
                 (unsigned)id,
                 browse,
                 display,
                 value);
    } else {
        LOG_ERROR("[BUILD][TEL-DOUBLE] FAIL NodeId=ns=%u;i=%u Browse=%s Display=%s Result=%s",
                  (unsigned)nsIdx,
                  (unsigned)id,
                  browse,
                  display,
                  statusNameSafe(rc));
    }
}
static void addTelemetryInt32(UA_Server *server, UA_NodeId parent,
                              UA_UInt32 id,
                              const char *browse,
                              const char *display,
                              UA_Int32 value) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Variant_setScalar(&attr.value, &value, &UA_TYPES[UA_TYPES_INT32]);
    attr.displayName = UA_LOCALIZEDTEXT("fr-FR", (char*)display);
    attr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ;
    attr.userAccessLevel = UA_ACCESSLEVELMASK_READ;

    UA_StatusCode rc = UA_Server_addVariableNode(server,
        nid(id),
        parent,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(nsIdx, (char*)browse),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        attr,
        NULL,
        NULL);

    if(rc == UA_STATUSCODE_GOOD) {
        LOG_INFO("[BUILD][TEL-INT32] OK Parent=ns=%u;i=%u NodeId=ns=%u;i=%u Browse=%s Display=%s Initial=%d",
                 (unsigned)parent.namespaceIndex,
                 (unsigned)(parent.identifierType == UA_NODEIDTYPE_NUMERIC ? parent.identifier.numeric : 0),
                 (unsigned)nsIdx,
                 (unsigned)id,
                 browse,
                 display,
                 value);
    } else {
        LOG_ERROR("[BUILD][TEL-INT32] FAIL NodeId=ns=%u;i=%u Browse=%s Display=%s Result=%s",
                  (unsigned)nsIdx,
                  (unsigned)id,
                  browse,
                  display,
                  statusNameSafe(rc));
    }
}

static CommandNodeContext *addCommandBool(UA_Server *server, UA_NodeId parent,
                                          UA_UInt32 id,
                                          const char *browse,
                                          const char *display,
                                          UA_Boolean initialValue,
                                          unsigned int allowedRoles,
                                          CommandMode mode) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[UA_TYPES_BOOLEAN]);
    attr.displayName = UA_LOCALIZEDTEXT("fr-FR", (char*)display);
    attr.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    attr.userAccessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    CommandNodeContext *ctx = allocateCommandContext(id, browse, display, initialValue, allowedRoles, mode);
    if(!ctx) {
        LOG_FATAL("[BUILD][CMD] Allocation mémoire échouée pour %s", display);
        return NULL;
    }

    UA_CallbackValueSource cvs;
    memset(&cvs, 0, sizeof(cvs));
    cvs.read = commandReadCallback;
    cvs.write = commandWriteCallback;

    UA_StatusCode rc = UA_Server_addCallbackValueSourceVariableNode(
        server,
        nid(id),
        parent,
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME(nsIdx, (char*)browse),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        attr,
        cvs,
        ctx,
        NULL
    );

    if(rc != UA_STATUSCODE_GOOD) {
        LOG_FATAL("[BUILD][CMD] FAIL NodeId=ns=%u;i=%u Browse=%s Display=%s AllowedRoles=%s Mode=%s Result=%s",
                  (unsigned)nsIdx,
                  (unsigned)id,
                  browse,
                  display,
                  rolesToString(allowedRoles),
                  modeToString(mode),
                  statusNameSafe(rc));
        return NULL;
    }

    LOG_INFO("[BUILD][CMD] OK Parent=ns=%u;i=%u NodeId=ns=%u;i=%u Browse=%s Display=%s AllowedRoles=%s Mode=%s",
             (unsigned)parent.namespaceIndex,
             (unsigned)(parent.identifierType == UA_NODEIDTYPE_NUMERIC ? parent.identifier.numeric : 0),
             (unsigned)nsIdx,
             (unsigned)id,
             browse,
             display,
             rolesToString(allowedRoles),
             modeToString(mode));

    return ctx;
}

/* =========================================================
 * FACTORY
 * ========================================================= */
static void buildMESHealth(UA_Server *server, UA_NodeId root) {
    LOG_INFO("[BUILD][SECTION] Début buildMESHealth");

    UA_NodeId mes = addObject(server, root, ID_MES_HEALTH, "MESHealth", "MESHealth");

    addTelemetryInt32(server, mes, ID_MES_HEARTBEAT, "Heartbeat", "Heartbeat", 0);
    addTelemetryInt32(server, mes, ID_MES_WATCHDOG, "Watchdog", "Watchdog", 0);
    addTelemetryInt32(server, mes, ID_MES_PROGRAM_VERSION, "ProgramVersion", "ProgramVersion", 200);
    addTelemetryInt32(server, mes, ID_MES_LAST_UPDATE_EPOCH, "LastUpdateEpoch", "LastUpdateEpoch", 0);
    addTelemetryBool(server, mes, ID_MES_DATA_STALE, "DataStale", "DataStale", false);

    LOG_INFO("[BUILD][SECTION] Fin buildMESHealth");
}

static void buildFactory(UA_Server *server, UA_NodeId root) {
    LOG_INFO("[BUILD][SECTION] Début buildFactory");

    UA_NodeId usine = addObject(server, root, ID_USINE, "Usine", "Usine");
    UA_NodeId controleur = addObject(server, usine, ID_USINE_CONTROLEUR, "Controleur", "Controleur");
    UA_NodeId commandes = addObject(server, usine, 1162, "Commandes", "Commandes");
    UA_NodeId cuves = addObject(server, usine, ID_USINE_CUVES, "Cuves", "Cuves");
    UA_NodeId capteurs = addObject(server, usine, ID_USINE_CAPTEURS, "Capteurs", "Capteurs");
    UA_NodeId actionneurs = addObject(server, usine, ID_USINE_ACTIONNEURS, "Actionneurs", "Actionneurs");
    UA_NodeId etat = addObject(server, usine, ID_USINE_ETAT_PROCESSUS, "EtatProcessus", "EtatProcessus");

    addCommandBool(server, controleur, ID_COMMANDE_DEMARRAGE, "CommandeDemarrage", "CommandeDemarrage", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, commandes, ID_ACTIVATION_CUVE1_CMD, "ActivationCuve1Commande", "ActivationCuve1Commande", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, commandes, ID_DCY_CMD, "DCY", "DCY", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_PULSE);
    addCommandBool(server, commandes, ID_ACTIVATION_CUVE2_CMD, "ActivationCuve2Commande", "ActivationCuve2Commande", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, commandes, ID_ACTIVATION_CUVE3_CMD, "ActivationCuve3Commande", "ActivationCuve3Commande", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);

    addTelemetryBool(server, controleur, ID_ETAT_USINE, "EtatUsine", "EtatUsine", false);
    addTelemetryBool(server, controleur, ID_ETAT_INSTALLATION, "EtatInstallation", "EtatInstallation", false);

    UA_NodeId cuve1 = addObject(server, cuves, ID_CUVE1, "TK1", "TK1");
    UA_NodeId cuve2 = addObject(server, cuves, ID_CUVE2, "TK2", "TK2");
    UA_NodeId cuve3 = addObject(server, cuves, ID_CUVE3, "TK3", "TK3");
    UA_NodeId cuve4 = addObject(server, cuves, ID_CUVE4, "TK4", "TK4");
    UA_NodeId cuve5 = addObject(server, cuves, ID_CUVE5, "TK5", "TK5");

    addTelemetryBool(server, cuve1, ID_CUVE1_NIVEAU_BAS, "NiveauBas", "NiveauBas", false);
    addTelemetryBool(server, cuve1, ID_CUVE1_NIVEAU_HAUT, "NiveauHaut", "NiveauHaut", false);
    addTelemetryBool(server, cuve2, ID_CUVE2_NIVEAU_BAS, "NiveauBas", "NiveauBas", false);
    addTelemetryBool(server, cuve2, ID_CUVE2_NIVEAU_HAUT, "NiveauHaut", "NiveauHaut", false);
    addTelemetryBool(server, cuve3, ID_CUVE3_NIVEAU_BAS, "NiveauBas", "NiveauBas", false);
    addTelemetryBool(server, cuve3, ID_CUVE3_NIVEAU_HAUT, "NiveauHaut", "NiveauHaut", false);
    addTelemetryBool(server, cuve4, ID_CUVE4_NIVEAU_BAS, "NiveauBas", "NiveauBas", false);
    addTelemetryBool(server, cuve4, ID_CUVE4_NIVEAU_HAUT, "NiveauHaut", "NiveauHaut", false);
    addTelemetryBool(server, cuve5, ID_CUVE5_NIVEAU_BAS, "NiveauBas", "NiveauBas", false);
    addTelemetryBool(server, cuve5, ID_CUVE5_NIVEAU_HAUT, "NiveauHaut", "NiveauHaut", false);

    addTelemetryBool(server, capteurs, ID_CAPTEUR_BV, "CapteurBouteilleVerte", "CapteurBouteilleVerte", false);
    addTelemetryBool(server, capteurs, ID_CAPTEUR_BR, "CapteurBouteilleRouge", "CapteurBouteilleRouge", false);
    addTelemetryBool(server, capteurs, ID_CAPTEUR_BB, "CapteurBouteilleBleue", "CapteurBouteilleBleue", false);

    addTelemetryBool(server, actionneurs, ID_ELECTROVANNE4, "Electrovanne4", "Electrovanne4", false);
    addTelemetryBool(server, actionneurs, ID_ELECTROVANNE5, "Electrovanne5", "Electrovanne5", false);
    addTelemetryBool(server, actionneurs, ID_POMPE1, "Pompe1", "Pompe1", false);
    addTelemetryBool(server, actionneurs, ID_ELECTROVANNE1, "Electrovanne1", "Electrovanne1", false);
    addTelemetryBool(server, actionneurs, ID_ELECTROVANNE2, "Electrovanne2", "Electrovanne2", false);
    addTelemetryBool(server, actionneurs, ID_ELECTROVANNE3, "Electrovanne3", "Electrovanne3", false);
    addTelemetryBool(server, actionneurs, ID_MIXEUR, "Mixeur", "Mixeur", false);
    addTelemetryBool(server, actionneurs, ID_CONVOYEUR, "Convoyeur", "Convoyeur", false);
    addTelemetryBool(server, actionneurs, ID_TETE_BOUCHAGE, "TeteBouchage", "TeteBouchage", false);
    addTelemetryBool(server, actionneurs, ID_BOUCHAGE, "Bouchage", "Bouchage", false);

    addTelemetryBool(server, etat, ID_ACTIVATION_CUVE1, "ActivationCuve1", "ActivationCuve1", false);
    addTelemetryBool(server, etat, ID_ACTIVATION_CUVE2, "ActivationCuve2", "ActivationCuve2", false);
    addTelemetryBool(server, etat, ID_ACTIVATION_CUVE3, "ActivationCuve3", "ActivationCuve3", false);
    addTelemetryBool(server, etat, ID_CYCLE_ACTIF, "CycleActif", "CycleActif", false);
    addTelemetryBool(server, etat, ID_RECYCLAGE_ACTIF, "RecyclageActif", "RecyclageActif", false);
    addTelemetryBool(server, etat, ID_CYCLE_TERMINE, "CycleTermine", "CycleTermine", false);
    UA_NodeId mes = addObject(server, usine, ID_FACTORY_MES, "MES", "MES"); 
    addTelemetryBool(server, mes, ID_FACTORY_MES_CYCLE_ACTIVE, "CycleActive", "CycleActive", false);
    addTelemetryBool(server, mes, ID_FACTORY_MES_CYCLE_DONE, "CycleDone", "CycleDone", false);
    addTelemetryBool(server, mes, ID_FACTORY_MES_FACTORY_RUNNING, "FactoryRunning", "FactoryRunning", false);
    addTelemetryBool(server, mes, ID_FACTORY_MES_RECYCLE_ACTIVE, "RecycleActive", "RecycleActive", false);
    addTelemetryBool(server, mes, ID_FACTORY_MES_TANK4_HIGH_SH, "Tank4HighShadow", "Tank4HighShadow", false);
    addTelemetryBool(server, mes, ID_FACTORY_MES_TANK4_LOW_SH, "Tank4LowShadow", "Tank4LowShadow", false);
    addTelemetryBool(server, mes, ID_FACTORY_MES_TANK5_HIGH_SH, "Tank5HighShadow", "Tank5HighShadow", false);
    addTelemetryBool(server, mes, ID_FACTORY_MES_TANK5_LOW_SH, "Tank5LowShadow", "Tank5LowShadow", false);

    /* Factory MES numeric counters */
    addTelemetryInt32(server, mes, ID_FACTORY_MES_HEARTBEAT, "Heartbeat", "Heartbeat", 0);
    addTelemetryInt32(server, mes, ID_FACTORY_MES_PROGRAM_VERSION, "ProgramVersion", "ProgramVersion", 0);
    addTelemetryInt32(server, mes, ID_FACTORY_MES_DEFAUT_CODE, "DefautCode", "DefautCode", 0);
    addTelemetryInt32(server, mes, ID_FACTORY_MES_STATE_WORD, "StateWord", "StateWord", 0);
    addTelemetryInt32(server, mes, ID_FACTORY_MES_CYCLE_COUNT, "CycleCount", "CycleCount", 0);
    addTelemetryInt32(server, mes, ID_FACTORY_MES_RUNTIME_SECONDS, "RunTimeSeconds", "RunTimeSeconds", 0);
    addTelemetryInt32(server, mes, ID_FACTORY_MES_GOOD_COUNT, "GoodCount", "GoodCount", 0);
    addTelemetryInt32(server, mes, ID_FACTORY_MES_TOTAL_CYCLES,     "TotalCycles", "TotalCycles", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_TOTAL_GOOD,       "TotalGood", "TotalGood", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_TOTAL_REJECT,     "TotalReject", "TotalReject", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_THROUGHPUT_MIN,   "ThroughputPerMin", "ThroughputPerMin", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_THROUGHPUT_HOUR,  "ThroughputPerHour", "ThroughputPerHour", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_QUALITY_PCT,      "QualityPercent", "QualityPercent", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_DOWNTIME_SEC,     "DowntimeSeconds", "DowntimeSeconds", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_UPTIME_SEC,       "UptimeSeconds", "UptimeSeconds", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_AVAILABILITY_PCT, "AvailabilityPercent", "AvailabilityPercent", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_TARGET_CT,        "TargetCycleTime", "TargetCycleTime", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_ACTUAL_CT,        "ActualCycleTime", "ActualCycleTime", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_PERFORMANCE_PCT,  "PerformancePercent", "PerformancePercent", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_OEE,              "OEE", "OEE", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_ENERGY_PER_CYCLE, "EnergyPerCycle", "EnergyPerCycle", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_ENERGY_PER_HOUR,  "EnergyPerHour", "EnergyPerHour", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_FAULT_TYPE_ADV,   "FaultTypeAdv", "FaultTypeAdv", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_WATCHDOG_ADV,     "WatchdogAdv", "WatchdogAdv", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_PROCESS_STATE,    "ProcessState", "ProcessState", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_PUMP_RUNTIME_H,   "PumpRuntimeHours", "PumpRuntimeHours", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_MAINT_DUE,        "MaintenanceDue", "MaintenanceDue", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_LOAD_PCT,         "LoadPercent", "LoadPercent", 0);
addTelemetryInt32(server, mes, ID_FACTORY_MES_INTEGRITY_ADV,    "IntegrityAdv", "IntegrityAdv", 0);
    LOG_INFO("[BUILD][SECTION] Fin buildFactory");
}

/* =========================================================
 * RAIL MANUAL
 * ========================================================= */

static void buildRailManual(UA_Server *server, UA_NodeId root) {
    LOG_INFO("[BUILD][SECTION] Début buildRailManual");

    UA_NodeId rail = addObject(server, root, ID_RAIL_MANUEL, "RailManuel", "RailManuel");
    UA_NodeId fes = addObject(server, rail, ID_LIGNE_FES, "LigneFes", "LigneFes");
    UA_NodeId marrakech = addObject(server, rail, ID_LIGNE_MARRAKECH, "LigneMarrakech", "LigneMarrakech");
    UA_NodeId commun = addObject(server, rail, ID_COMMUN, "Commun", "Commun");

    addCommandBool(server, fes, ID_VANNE1, "Vanne1", "Vanne1", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, fes, ID_VANNE2, "Vanne2", "Vanne2", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, fes, ID_VANNE3, "Vanne3", "Vanne3", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, fes, ID_VANNE4, "Vanne4", "Vanne4", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, fes, ID_FES_ACTIVATION, "ActivationLigne", "ActivationLigne", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);

    addTelemetryBool(server, fes, ID_SV1, "SignalActivation1", "SignalActivation1", false);
    addTelemetryBool(server, fes, ID_SV2, "SignalActivation2", "SignalActivation2", false);
    addTelemetryBool(server, fes, ID_SV3, "SignalActivation3", "SignalActivation3", false);
    addTelemetryBool(server, fes, ID_SV4, "SignalActivation4", "SignalActivation4", false);
    addTelemetryBool(server, fes, ID_OD1, "DelaiOuverture1", "DelaiOuverture1", false);
    addTelemetryBool(server, fes, ID_OD2, "DelaiOuverture2", "DelaiOuverture2", false);
    addTelemetryBool(server, fes, ID_OD3, "DelaiOuverture3", "DelaiOuverture3", false);
    addTelemetryBool(server, fes, ID_OD4, "DelaiOuverture4", "DelaiOuverture4", false);
    addTelemetryBool(server, fes, ID_CD1, "DelaiFermeture1", "DelaiFermeture1", false);
    addTelemetryBool(server, fes, ID_CD2, "DelaiFermeture2", "DelaiFermeture2", false);
    addTelemetryBool(server, fes, ID_CD3, "DelaiFermeture3", "DelaiFermeture3", false);
    addTelemetryBool(server, fes, ID_CD4, "DelaiFermeture4", "DelaiFermeture4", false);

    addCommandBool(server, marrakech, ID_VANNE11, "Vanne11", "Vanne11", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, marrakech, ID_VANNE12, "Vanne12", "Vanne12", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, marrakech, ID_VANNE13, "Vanne13", "Vanne13", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, marrakech, ID_VANNE14, "Vanne14", "Vanne14", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addCommandBool(server, marrakech, ID_MARRAKECH_ACTIVATION, "ActivationLigne", "ActivationLigne", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);

    addTelemetryBool(server, commun, ID_CYCLE_FES_TERMINE, "CycleFesTermine", "CycleFesTermine", false);
    addCommandBool(server, commun, ID_RESET_FES, "ResetFes", "ResetFes", false,
                   ROLE_ADMIN, CMD_MODE_PULSE);
    addTelemetryBool(server, commun, ID_CYCLE_MARRAKECH_TERMINE, "CycleMarrakechTermine", "CycleMarrakechTermine", false);
    addCommandBool(server, commun, ID_RESET_MARRAKECH, "ResetMarrakech", "ResetMarrakech", false,
                   ROLE_ADMIN, CMD_MODE_PULSE);
    UA_NodeId mes = addObject(server, rail, ID_RAIL_MANUAL_MES, "MES", "MES");
    addTelemetryBool(server, mes, ID_RAIL_MANUAL_MES_FES_ROUTE_VALID, "FESRouteValid", "FESRouteValid", false);
    addTelemetryBool(server, mes, ID_RAIL_MANUAL_MES_MARR_ROUTE_VALID, "MarrakechRouteValid", "MarrakechRouteValid", false);
    addTelemetryBool(server, mes, ID_RAIL_MANUAL_MES_FES_ACTIVE, "FESCycleActive", "FESCycleActive", false);
    addTelemetryBool(server, mes, ID_RAIL_MANUAL_MES_MARR_ACTIVE, "MarrakechCycleActive", "MarrakechCycleActive", false);
    addTelemetryBool(server, mes, ID_RAIL_MANUAL_MES_DIR_CONFLICT, "DirectionConflict", "DirectionConflict", false);
    addTelemetryBool(server, mes, ID_RAIL_MANUAL_MES_GLOBAL_FAULT, "GlobalFault", "GlobalFault", false);
    addTelemetryBool(server, mes, ID_RAIL_MANUAL_MES_ANIMATION_ALIVE, "AnimationAlive", "AnimationAlive", false);
    addTelemetryBool(server, mes, ID_RAIL_MANUAL_MES_FES_DONE, "FESDone", "FESDone", false);
    addTelemetryBool(server, mes, ID_RAIL_MANUAL_MES_MARR_DONE, "MarrakechDone", "MarrakechDone", false);

    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_FES_COUNT, "FESCycleCount", "FESCycleCount", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_MARR_COUNT, "MarrakechCycleCount", "MarrakechCycleCount", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_TOTAL_COUNT, "TotalCycleCount", "TotalCycleCount", 0);

    /* RailManual MES numeric health / diagnostics */
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_HEARTBEAT, "Heartbeat", "Heartbeat", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_PROGRAM_VERSION, "ProgramVersion", "ProgramVersion", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_GLOBAL_FAULT_CODE, "GlobalFaultCode", "GlobalFaultCode", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_STATE_WORD, "StateWord", "StateWord", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_LAST_RESET_REASON, "LastResetReason", "LastResetReason", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_LAST_SCAN_MS, "LastScanMs", "LastScanMs", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_MAX_SCAN_MS, "MaxScanMs", "MaxScanMs", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_WATCHDOG_LO, "WatchdogLo", "WatchdogLo", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_FES_ACTIVE_MS, "FESActiveMs", "FESActiveMs", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_MARR_ACTIVE_MS, "MarrakechActiveMs", "MarrakechActiveMs", 0);
    addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_ACTIVE_LINES,   "ActiveLines", "ActiveLines", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_ROUTE_MASK,     "RouteMask", "RouteMask", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_FLOW_COUNT,     "FlowCount", "FlowCount", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_FLOW_RATE,      "FlowRate", "FlowRate", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_UTIL_PCT,       "UtilizationPercent", "UtilizationPercent", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_CONFLICT_COUNT, "ConflictCount", "ConflictCount", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_SAFETY_FLAG,    "SafetyFlag", "SafetyFlag", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_QUEUE_LENGTH,   "QueueLength", "QueueLength", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_WAIT_TIME,      "WaitTime", "WaitTime", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_THROUGHPUT,     "Throughput", "Throughput", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_EFFICIENCY,     "Efficiency", "Efficiency", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_OEE,            "OEE", "OEE", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_STATE,          "State", "State", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_FAULT_TYPE_ADV, "FaultTypeAdv", "FaultTypeAdv", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_WATCHDOG_ADV,   "WatchdogAdv", "WatchdogAdv", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_INTEGRITY_ADV,  "IntegrityAdv", "IntegrityAdv", 0);
addTelemetryInt32(server, mes, ID_RAIL_MANUAL_MES_LOAD_PCT,       "LoadPercent", "LoadPercent", 0);
    LOG_INFO("[BUILD][SECTION] Fin buildRailManual");
}

/* =========================================================
 * RAIL AUTO
 * ========================================================= */

static void buildRailAuto(UA_Server *server, UA_NodeId root) {
    LOG_INFO("[BUILD][SECTION] Début buildRailAuto");

    UA_NodeId rail = addObject(server, root, ID_RAIL_AUTO, "RailAuto", "RailAuto");
    UA_NodeId cycle = addObject(server, rail, ID_CYCLE, "Cycle", "Cycle");
    UA_NodeId etape1 = addObject(server, rail, ID_ETAPE1, "Etape1", "Etape1");
    UA_NodeId etape2 = addObject(server, rail, ID_ETAPE2, "Etape2", "Etape2");
    UA_NodeId etape3 = addObject(server, rail, ID_ETAPE3, "Etape3", "Etape3");
    UA_NodeId etape4 = addObject(server, rail, ID_ETAPE4, "Etape4", "Etape4");

    addCommandBool(server, cycle, ID_DECLENCHEUR_CYCLE, "DeclencheurCycle", "DeclencheurCycle", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_PULSE);

    addTelemetryBool(server, etape1, ID_ETAPE1_ACTIVATION, "Activation", "Activation", false);
    addTelemetryBool(server, etape1, ID_ETAPE1_OUVERTURE, "DelaiOuverture", "DelaiOuverture", false);
    addTelemetryBool(server, etape1, ID_ETAPE1_FERMETURE, "DelaiFermeture", "DelaiFermeture", false);
    addTelemetryBool(server, etape1, ID_ETAPE1_TERMINEE, "EtapeTerminee", "EtapeTerminee", false);
    addCommandBool(server, etape1, ID_ETAPE1_RESET, "ResetEtape", "ResetEtape", false,
                   ROLE_ADMIN, CMD_MODE_PULSE);

    addTelemetryBool(server, etape2, ID_ETAPE2_ACTIVATION, "Activation", "Activation", false);
    addTelemetryBool(server, etape2, ID_ETAPE2_OUVERTURE, "DelaiOuverture", "DelaiOuverture", false);
    addTelemetryBool(server, etape2, ID_ETAPE2_FERMETURE, "DelaiFermeture", "DelaiFermeture", false);
    addTelemetryBool(server, etape2, ID_ETAPE2_TERMINEE, "EtapeTerminee", "EtapeTerminee", false);
    addCommandBool(server, etape2, ID_ETAPE2_RESET, "ResetEtape", "ResetEtape", false,
                   ROLE_ADMIN, CMD_MODE_PULSE);

    addTelemetryBool(server, etape3, ID_ETAPE3_ACTIVATION, "Activation", "Activation", false);
    addTelemetryBool(server, etape3, ID_ETAPE3_OUVERTURE, "DelaiOuverture", "DelaiOuverture", false);
    addTelemetryBool(server, etape3, ID_ETAPE3_FERMETURE, "DelaiFermeture", "DelaiFermeture", false);
    addTelemetryBool(server, etape3, ID_ETAPE3_TERMINEE, "EtapeTerminee", "EtapeTerminee", false);
    addCommandBool(server, etape3, ID_ETAPE3_RESET, "ResetEtape", "ResetEtape", false,
                   ROLE_ADMIN, CMD_MODE_PULSE);

    addTelemetryBool(server, etape4, ID_ETAPE4_ACTIVATION, "Activation", "Activation", false);
    addTelemetryBool(server, etape4, ID_ETAPE4_OUVERTURE, "DelaiOuverture", "DelaiOuverture", false);
    addTelemetryBool(server, etape4, ID_ETAPE4_FERMETURE, "DelaiFermeture", "DelaiFermeture", false);
    addTelemetryBool(server, etape4, ID_ETAPE4_TERMINEE, "EtapeTerminee", "EtapeTerminee", false);
    addCommandBool(server, etape4, ID_ETAPE4_RESET, "ResetEtape", "ResetEtape", false,
                   ROLE_ADMIN, CMD_MODE_PULSE);
UA_NodeId mes = addObject(server, rail, 1360, "MES", "MES");

addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_STEP,         "Step", "Step", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_PROGRESS_PCT, "ProgressPercent", "ProgressPercent", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_CYCLE_ACTIVE, "CycleActive", "CycleActive", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_CYCLE_DONE,   "CycleDone", "CycleDone", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_ERROR_CODE,   "ErrorCode", "ErrorCode", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_STEP_TIME,    "StepTime", "StepTime", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_TOTAL_TIME,   "TotalTime", "TotalTime", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_THROUGHPUT,   "Throughput", "Throughput", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_AVAILABILITY, "Availability", "Availability", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_PERFORMANCE,  "Performance", "Performance", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_QUALITY,      "Quality", "Quality", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_OEE,          "OEE", "OEE", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_WATCHDOG,     "Watchdog", "Watchdog", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_STATE,        "State", "State", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_FAULT_TYPE,   "FaultType", "FaultType", 0);
addTelemetryInt32(server, mes, ID_RAIL_AUTO_MES_INTEGRITY,    "Integrity", "Integrity", 0);
    LOG_INFO("[BUILD][SECTION] Fin buildRailAuto");
}

/* =========================================================
 * POWERGRID PLC1
 * ========================================================= */

static void buildPLC1(UA_Server *server, UA_NodeId parent) {
    LOG_INFO("[BUILD][SECTION] Début buildPLC1");

    UA_NodeId plc1 = addObject(server, parent, ID_PLC1, "PLC1", "PLC1");

    UA_NodeId sources = addObject(server, plc1, ID_PLC1_SOURCES, "Sources", "Sources");
    UA_NodeId charges = addObject(server, plc1, ID_PLC1_CHARGES, "Charges", "Charges");

    UA_NodeId pe = addObject(server, sources, ID_PLC1_PE, "PE", "PE");
    addCommandBool(server, pe, ID_PLC1_PE_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, pe, ID_PLC1_PE_ETAT, "Etat", "Etat", false);

    UA_NodeId fs = addObject(server, sources, ID_PLC1_FS, "FS", "FS");
    addCommandBool(server, fs, ID_PLC1_FS_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, fs, ID_PLC1_FS_ETAT, "Etat", "Etat", false);

    UA_NodeId gs = addObject(server, sources, ID_PLC1_GS, "GS", "GS");
    addCommandBool(server, gs, ID_PLC1_GS_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, gs, ID_PLC1_GS_ETAT, "Etat", "Etat", false);

    UA_NodeId factory = addObject(server, charges, ID_PLC1_FACTORY, "Factory", "Factory");
    addCommandBool(server, factory, ID_PLC1_FACTORY_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, factory, ID_PLC1_FACTORY_ETAT, "Etat", "Etat", false);

    UA_NodeId homes = addObject(server, charges, ID_PLC1_HOMES, "Homes", "Homes");
    addCommandBool(server, homes, ID_PLC1_HOMES_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, homes, ID_PLC1_HOMES_ETAT, "Etat", "Etat", false);

    UA_NodeId rail = addObject(server, charges, ID_PLC1_RAILWAY, "Railway", "Railway");
    addCommandBool(server, rail, ID_PLC1_RAILWAY_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, rail, ID_PLC1_RAILWAY_ETAT, "Etat", "Etat", false);
UA_NodeId mes = addObject(server, plc1, 1440, "MES", "MES");

addTelemetryInt32(server, mes, ID_PLC1_MES_SRC_COUNT,  "SourceCount", "SourceCount", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_LOAD_COUNT, "LoadCount", "LoadCount", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_GRID_ON,    "GridOn", "GridOn", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_LOAD_PCT,   "LoadPercent", "LoadPercent", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_SRC_PCT,    "SourcePercent", "SourcePercent", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_GRID_STATE, "GridState", "GridState", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_SRC_MASK,   "SourceMask", "SourceMask", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_LOAD_MASK,  "LoadMask", "LoadMask", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_GRID_READY, "GridReady", "GridReady", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_OVERLOAD,   "Overload", "Overload", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_FAULT_TYPE, "FaultType", "FaultType", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_WATCHDOG,   "Watchdog", "Watchdog", 0);
addTelemetryInt32(server, mes, ID_PLC1_MES_INTEGRITY,  "Integrity", "Integrity", 0);
    LOG_INFO("[BUILD][SECTION] Fin buildPLC1");
}

/* =========================================================
 * POWERGRID PLC2
 * ========================================================= */

static void buildPLC2(UA_Server *server, UA_NodeId parent) {
    LOG_INFO("[BUILD][SECTION] Début buildPLC2");

    UA_NodeId plc2 = addObject(server, parent, ID_PLC2, "PLC2", "PLC2");

    UA_NodeId sources = addObject(server, plc2, ID_PLC2_SOURCES, "Sources", "Sources");
    UA_NodeId charges = addObject(server, plc2, ID_PLC2_CHARGES, "Charges", "Charges");
    UA_NodeId production = addObject(server, plc2, ID_PLC2_PRODUCTION, "Production", "Production");
    UA_NodeId distribution = addObject(server, plc2, ID_PLC2_DISTRIBUTION, "Distribution", "Distribution");
    UA_NodeId metrics = addObject(server, plc2, ID_PLC2_METRICS, "Mesures", "Mesures");

    UA_NodeId pe = addObject(server, sources, ID_PLC2_PE, "PE", "PE");
    addCommandBool(server, pe, ID_PLC2_PE_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, pe, ID_PLC2_PE_ETAT, "Etat", "Etat", false);
    addTelemetryBool(server, pe, ID_PLC2_PE_PROD, "Production", "Production", false);
    addTelemetryDouble(server, pe, ID_PLC2_PE_POWER, "Power", "Power", 42.11);

    UA_NodeId fs = addObject(server, sources, ID_PLC2_FS, "FS", "FS");
    addCommandBool(server, fs, ID_PLC2_FS_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, fs, ID_PLC2_FS_ETAT, "Etat", "Etat", false);
    addTelemetryBool(server, fs, ID_PLC2_FS_PROD, "Production", "Production", false);
    addTelemetryDouble(server, fs, ID_PLC2_FS_POWER, "Power", "Power", 205.6);

    UA_NodeId gs = addObject(server, sources, ID_PLC2_GS, "GS", "GS");
    addCommandBool(server, gs, ID_PLC2_GS_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, gs, ID_PLC2_GS_ETAT, "Etat", "Etat", false);
    addTelemetryBool(server, gs, ID_PLC2_GS_PROD, "Production", "Production", false);
    addTelemetryDouble(server, gs, ID_PLC2_GS_POWER, "Power", "Power", 406.83);

    UA_NodeId factory = addObject(server, charges, ID_PLC2_FACTORY, "Factory", "Factory");
    addCommandBool(server, factory, ID_PLC2_FACTORY_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, factory, ID_PLC2_FACTORY_ETAT, "Etat", "Etat", false);
    addTelemetryBool(server, factory, ID_PLC2_FACTORY_DIST, "Distribue", "Distribue", false);

    UA_NodeId homes = addObject(server, charges, ID_PLC2_HOMES, "Homes", "Homes");
    addCommandBool(server, homes, ID_PLC2_HOMES_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, homes, ID_PLC2_HOMES_ETAT, "Etat", "Etat", false);
    addTelemetryBool(server, homes, ID_PLC2_HOMES_DIST, "Distribue", "Distribue", false);

    UA_NodeId railway = addObject(server, charges, ID_PLC2_RAILWAY, "Railway", "Railway");
    addCommandBool(server, railway, ID_PLC2_RAILWAY_SWITCH, "Switch", "Switch", false,
                   ROLE_ADMIN | ROLE_SCADA, CMD_MODE_MAINTAINED);
    addTelemetryBool(server, railway, ID_PLC2_RAILWAY_ETAT, "Etat", "Etat", false);
    addTelemetryBool(server, railway, ID_PLC2_RAILWAY_DIST, "Distribue", "Distribue", false);

    addTelemetryBool(server, production, ID_PLC2_B1, "B1", "B1", false);
    addTelemetryBool(server, production, ID_PLC2_B2, "B2", "B2", false);
    addTelemetryBool(server, production, ID_PLC2_B3, "B3", "B3", false);
    addTelemetryBool(server, production, ID_PLC2_B4, "B4", "B4", false);
    addTelemetryBool(server, production, ID_PLC2_PRODUCTION_STATE, "EtatProduction", "EtatProduction", false);

    addTelemetryBool(server, distribution, ID_PLC2_B5, "B5", "B5", false);
    addTelemetryBool(server, distribution, ID_PLC2_B6, "B6", "B6", false);
    addTelemetryBool(server, distribution, ID_PLC2_B7, "B7", "B7", false);

    addTelemetryBool(server, distribution, ID_PLC2_FACTORY_DIST_STATE, "FactoryDistribue", "FactoryDistribue", false);
    addTelemetryBool(server, distribution, ID_PLC2_HOMES_DIST_STATE, "HomesDistribue", "HomesDistribue", false);
    addTelemetryBool(server, distribution, ID_PLC2_RAILWAY_DIST_STATE, "RailwayDistribue", "RailwayDistribue", false);

    addTelemetryDouble(server, metrics, ID_PLC2_TAP, "TAP", "TAP", 42.11 + 205.6 + 406.83);
    addTelemetryDouble(server, metrics, ID_PLC2_TCP, "TCP", "TCP", 0.0);
    UA_NodeId mes = addObject(server, plc2, ID_PLC2_MES, "MES", "MES");
    addTelemetryBool(server, mes, ID_PLC2_MES_FACTORY_SERVED, "FactoryServed", "FactoryServed", false);
    addTelemetryBool(server, mes, ID_PLC2_MES_HOMES_SERVED, "HomesServed", "HomesServed", false);
    addTelemetryBool(server, mes, ID_PLC2_MES_RAILWAY_SERVED, "RailwayServed", "RailwayServed", false);
    addTelemetryBool(server, mes, ID_PLC2_MES_DEFICIT_ACTIVE, "DeficitActive", "DeficitActive", false);

    addTelemetryDouble(server, mes, ID_PLC2_MES_LOSSES, "Losses", "Losses", 0.0);
    addTelemetryDouble(server, mes, ID_PLC2_MES_RESERVE_MARGIN, "ReserveMargin", "ReserveMargin", 0.0);
    addTelemetryDouble(server, mes, ID_PLC2_MES_FACTORY_DEMAND, "FactoryDemand", "FactoryDemand", 0.0);
    addTelemetryDouble(server, mes, ID_PLC2_MES_HOMES_DEMAND, "HomesDemand", "HomesDemand", 0.0);
    addTelemetryDouble(server, mes, ID_PLC2_MES_RAILWAY_DEMAND, "RailwayDemand", "RailwayDemand", 0.0);

    /* PowerGrid PLC2 extra MES real values */
    addTelemetryDouble(server, mes, ID_PLC2_MES_PE_POWER_VALUE, "PEPowerValue", "PEPowerValue", 0.0);
    addTelemetryDouble(server, mes, ID_PLC2_MES_FS_POWER_VALUE, "FSPowerValue", "FSPowerValue", 0.0);
    addTelemetryDouble(server, mes, ID_PLC2_MES_GS_POWER_VALUE, "GSPowerValue", "GSPowerValue", 0.0);
    addTelemetryDouble(server, mes, ID_PLC2_MES_TOTAL_PRODUCTION, "TotalProduction", "TotalProduction", 0.0);
    addTelemetryDouble(server, mes, ID_PLC2_MES_TOTAL_CONSUMPTION, "TotalConsumption", "TotalConsumption", 0.0);
    addTelemetryDouble(server, mes, ID_PLC2_MES_RESERVE_VALUE, "ReserveValue", "ReserveValue", 0.0);
    addTelemetryInt32(server, mes, ID_PLC2_MES_PROD_ON,      "ProductionOn", "ProductionOn", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_SRC_CNT,      "SourceCount", "SourceCount", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_DIS_CNT,      "DistributionCount", "DistributionCount", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_DIS_PCT,      "DistributionPercent", "DistributionPercent", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_SRC_MASK,     "SourceMask", "SourceMask", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_DIS_MASK,     "DistributionMask", "DistributionMask", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_TAP_X10,      "TAPx10", "TAPx10", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_TCP_X10,      "TCPx10", "TCPx10", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_DEM_X10,      "Demandx10", "Demandx10", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_BAL_STAT,     "BalanceStatus", "BalanceStatus", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_BAL_ABS,      "BalanceAbs", "BalanceAbs", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_UTIL_PCT,     "UtilizationPercent", "UtilizationPercent", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_EN_STATE,     "EnergyState", "EnergyState", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_FAULT,        "Fault", "Fault", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_WATCHDOG,     "Watchdog", "Watchdog", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_INTEGRITY,    "Integrity", "Integrity", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_REQ_CNT,      "RequestCount", "RequestCount", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_REQ_MASK,     "RequestMask", "RequestMask", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_SERVED_X10,   "Servedx10", "Servedx10", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_UNSERVED_X10, "Unservedx10", "Unservedx10", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_SERVED_PCT,   "ServedPercent", "ServedPercent", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_FAC_DEM_X10,  "FactoryDemandx10", "FactoryDemandx10", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_HOME_DEM_X10, "HomesDemandx10", "HomesDemandx10", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_RAIL_DEM_X10, "RailwayDemandx10", "RailwayDemandx10", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_FAC_SHARE,    "FactoryShare", "FactoryShare", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_HOME_SHARE,   "HomesShare", "HomesShare", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_RAIL_SHARE,   "RailwayShare", "RailwayShare", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_FAC_SERVED,   "FactoryServedFlag", "FactoryServedFlag", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_HOME_SERVED,  "HomesServedFlag", "HomesServedFlag", 0);
addTelemetryInt32(server, mes, ID_PLC2_MES_RAIL_SERVED,  "RailwayServedFlag", "RailwayServedFlag", 0);
    LOG_INFO("[BUILD][SECTION] Fin buildPLC2");
}

static void buildPowerGrid(UA_Server *server, UA_NodeId root) {
    LOG_INFO("[BUILD][SECTION] Début buildPowerGrid");
    UA_NodeId pg = addObject(server, root, ID_POWERGRID, "PowerGrid", "PowerGrid");
    buildPLC1(server, pg);
    buildPLC2(server, pg);
    LOG_INFO("[BUILD][SECTION] Fin buildPowerGrid");
}

/* =========================================================
 * MAIN
 * ========================================================= */

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);
    ot_syslog_init();

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_Server *server = NULL;
    UA_ServerConfig *config = NULL;

    LOG_INFO("[BOOT] Démarrage du serveur OPC UA PowerGrid");

    server = UA_Server_new();
    if(!server) {
        LOG_FATAL("[BOOT] UA_Server_new a échoué");
        return EXIT_FAILURE;
    }

    config = UA_Server_getConfig(server);
    if(!config) {
        LOG_FATAL("[BOOT] UA_Server_getConfig a échoué");
        UA_Server_delete(server);
        return EXIT_FAILURE;
    }

    UA_ByteString certificate = loadFile("/app/pki/ApplCerts/own/certs/server.der");
    UA_ByteString privateKey  = loadFile("/app/pki/ApplCerts/own/private/server.key.der");

    if(certificate.length == 0 || privateKey.length == 0) {
        LOG_FATAL("[BOOT] Certificat ou clé privée introuvable / vide");
        retval = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    LOG_INFO("[BOOT] Initialisation filestore PKI...");
    UA_String storePath = UA_STRING("/app/pki");
    retval = UA_ServerConfig_setDefaultWithFilestore(
        config,
        SERVER_PORT,
        &certificate,
        &privateKey,
        storePath
    );

    if(retval != UA_STATUSCODE_GOOD) {
        LOG_FATAL("[BOOT] Initialisation Filestore échouée: %s", statusNameSafe(retval));
        goto cleanup;
    }

    LOG_INFO("[BOOT] Filestore PKI initialisé");

    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri = UA_STRING_ALLOC(SERVER_APP_URI);

    if(config->serverUrlsSize > 0) {
        UA_String_clear(&config->serverUrls[0]);
        config->serverUrls[0] = UA_STRING_ALLOC("opc.tcp://192.168.1.62:4840");
        config->serverUrlsSize = 1;
    }

    UA_LocalizedText_clear(&config->applicationDescription.applicationName);
    config->applicationDescription.applicationName = UA_LOCALIZEDTEXT_ALLOC("fr-FR", SERVER_NAME);

    LOG_INFO("[BOOT] ApplicationUri=%s", SERVER_APP_URI);
    LOG_INFO("[BOOT] ServerName=%s", SERVER_NAME);
    LOG_INFO("[BOOT] Port=%d", SERVER_PORT);

#if ENABLE_DISCOVERY_NONE
    LOG_INFO("[BOOT] Ajout de SecurityPolicy None pour discovery only...");
    retval = UA_ServerConfig_addSecurityPolicyNone(config, &certificate);
    if(retval == UA_STATUSCODE_GOOD) {
        config->securityPolicyNoneDiscoveryOnly = true;
        LOG_INFO("[BOOT] SecurityPolicy None activée pour discovery only");
    } else {
        LOG_WARN("[BOOT] Impossible d'ajouter SecurityPolicy None: %s", statusNameSafe(retval));
    }
#endif

    if(config->accessControl.clear) {
        LOG_INFO("[BOOT] Nettoyage de l'accessControl par défaut");
        config->accessControl.clear(&config->accessControl);
    }

    UA_UsernamePasswordLogin logins[3];
    logins[0].username = UA_STRING("admin");
    logins[0].password = UA_STRING("ChangeMe_Admin!");

    logins[1].username = UA_STRING("scada");
    logins[1].password = UA_STRING("ChangeMe_Scada!");

    logins[2].username = UA_STRING("historian");
    logins[2].password = UA_STRING("ChangeMe_Historian!");

    LOG_INFO("[BOOT] Configuration AccessControl avec 3 comptes locaux");
    const UA_String securePolicyUri =
        UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");

    retval = UA_AccessControl_default(config, false, &securePolicyUri, 3, logins);
    if(retval != UA_STATUSCODE_GOOD) {
        LOG_FATAL("[BOOT] Configuration AccessControl échouée: %s", statusNameSafe(retval));
        goto cleanup;
    }

    config->accessControl.activateSession = onActivateSession;
    config->accessControl.closeSession = onCloseSession;

    LOG_INFO("[BOOT] AccessControl configuré. Utilisateurs:");
    LOG_INFO("[BOOT]   - admin      -> %s", rolesToString(rolesForUsername("admin")));
    LOG_INFO("[BOOT]   - scada      -> %s", rolesToString(rolesForUsername("scada")));
    LOG_INFO("[BOOT]   - historian  -> %s", rolesToString(rolesForUsername("historian")));

    nsIdx = UA_Server_addNamespace(server, NS_URI);
    LOG_INFO("[BOOT] Namespace ajouté: NS_URI=%s -> nsIdx=%u", NS_URI, (unsigned)nsIdx);

    UA_NodeId centrale = addObject(server,
        UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
        ID_CENTRALE,
        "Centrale",
        "Centrale");

    buildMESHealth(server, centrale); 
    buildFactory(server, centrale);
    buildRailManual(server, centrale);
    buildRailAuto(server, centrale);
    buildPowerGrid(server, centrale);

    LOG_INFO("[BOOT] Configuration des collecteurs Modbus...");
    configurer_collecteurs_modbus(server, nsIdx);
    LOG_INFO("[BOOT] Collecteurs Modbus configurés");

    LOG_INFO("[BOOT] Serveur OPC UA sécurisé prêt sur opc.tcp://192.168.1.62:%d", SERVER_PORT);
    retval = UA_Server_run(server, &running);
    LOG_INFO("[SHUTDOWN] UA_Server_run terminé avec statut=%s", statusNameSafe(retval));

cleanup:
    LOG_INFO("[CLEANUP] Début du nettoyage");
    freeCommandContexts();
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);

    if(server) {
        UA_Server_delete(server);
        LOG_INFO("[CLEANUP] UA_Server_delete exécuté");
    }

    LOG_INFO("[CLEANUP] Fin du nettoyage");
    ot_syslog_close();
    return (retval == UA_STATUSCODE_GOOD) ? EXIT_SUCCESS : EXIT_FAILURE;
}
