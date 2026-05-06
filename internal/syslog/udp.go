package syslog

import (
	"context"
	"errors"
	"log/slog"
	"net"
)

func RunUDPServer(ctx context.Context, addr string, out chan<- IncomingLog, logger *slog.Logger) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer pc.Close()

	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	buf := make([]byte, 64*1024)
	logger.Info("udp syslog server listening", "addr", addr)
	for {
		n, remote, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if isClosedErr(err) {
				return nil
			}
			logger.Warn("udp read failed", "error", err)
			continue
		}

		msg := string(buf[:n])
		ip := ""
		if udpAddr, ok := remote.(*net.UDPAddr); ok {
			ip = udpAddr.IP.String()
		}

		select {
		case out <- IncomingLog{Raw: msg, SourceIP: ip, Transport: "udp"}:
		case <-ctx.Done():
			return nil
		}
	}
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed)
}

