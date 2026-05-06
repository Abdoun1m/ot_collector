package syslog

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
)

func RunTCPServer(ctx context.Context, addr string, out chan<- IncomingLog, logger *slog.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	logger.Info("tcp syslog server listening", "addr", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			logger.Warn("tcp accept failed", "error", err)
			continue
		}
		go handleTCPConn(ctx, conn, out, logger)
	}
}

func handleTCPConn(ctx context.Context, conn net.Conn, out chan<- IncomingLog, logger *slog.Logger) {
	defer conn.Close()

	ip := ""
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = tcpAddr.IP.String()
	}

	reader := bufio.NewReader(conn)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			logger.Warn("tcp read failed", "error", err)
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		select {
		case out <- IncomingLog{Raw: line, SourceIP: ip, Transport: "tcp"}:
		case <-ctx.Done():
			return
		}
	}
}

