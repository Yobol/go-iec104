package iec104

import (
	"crypto/tls"
	"github.com/sirupsen/logrus"
	"net"
)

func NewServer(address string, tc *tls.Config) *Server {
	return &Server{
		address: address,
		tc:      tc,
	}
}

// Server in IEC 104 is also called as slave or controlled station.
type Server struct {
	address  string
	tc       *tls.Config
	listener net.Listener

	lg *logrus.Logger
}

func (s *Server) Serve() error {
	if err := s.listen(); err != nil {
		return err
	}

	defer s.listener.Close()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.lg.Errorf("accept conn with %s", conn.RemoteAddr())
			continue
		}

		go s.serve(&Conn{
			conn,
		})
	}
}
func (s *Server) listen() error {
	if s.tc != nil {
		listener, err := tls.Listen("tcp", s.address, s.tc)
		if err != nil {
			return err
		}
		s.lg.Debugf("IEC104 server serve at %s with security: %+v", s.address, s.tc)
		s.listener = listener
	} else {
		listener, err := net.Listen("tcp", s.address)
		if err != nil {
			return err
		}
		s.lg.Debugf("IEC104 server serve at %s no security", s.address)
		s.listener = listener
	}
	return nil
}
func (s *Server) serve(conn *Conn) {
	s.lg.Debugf("serve connection from %s", conn.RemoteAddr())

	// TODO
}

type Conn struct {
	net.Conn
}
