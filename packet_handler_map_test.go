package quic

import (
	"bytes"
	"errors"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Handler Map", func() {
	var (
		handler *packetHandlerMap
		conn    *mockPacketConn
	)

	getPacket := func(connID protocol.ConnectionID) []byte {
		buf := &bytes.Buffer{}
		err := (&wire.Header{
			DestConnectionID: connID,
			PacketNumberLen:  protocol.PacketNumberLen1,
		}).Write(buf, protocol.PerspectiveServer, versionGQUICFrames)
		Expect(err).ToNot(HaveOccurred())
		return buf.Bytes()
	}

	BeforeEach(func() {
		conn = newMockPacketConn()
		handler = newPacketHandlerMap(conn, 5, utils.DefaultLogger).(*packetHandlerMap)
	})

	AfterEach(func() {
		// delete sessions and the server before closing
		// They might be mock implementations, and we'd have to register the expected calls before otherwise.
		handler.mutex.Lock()
		for connID := range handler.handlers {
			delete(handler.handlers, connID)
		}
		handler.server = nil
		handler.mutex.Unlock()
		handler.Close()
		Eventually(handler.listening).Should(BeClosed())
	})

	It("closes", func() {
		getMultiplexer() // make the sync.Once execute
		// replace the clientMuxer. getClientMultiplexer will now return the MockMultiplexer
		mockMultiplexer := NewMockMultiplexer(mockCtrl)
		origMultiplexer := connMuxer
		connMuxer = mockMultiplexer

		defer func() {
			connMuxer = origMultiplexer
		}()

		testErr := errors.New("test error	")
		sess1 := NewMockPacketHandler(mockCtrl)
		sess1.EXPECT().destroy(testErr)
		sess2 := NewMockPacketHandler(mockCtrl)
		sess2.EXPECT().destroy(testErr)
		handler.Add(protocol.ConnectionID{1, 1, 1, 1}, sess1)
		handler.Add(protocol.ConnectionID{2, 2, 2, 2}, sess2)
		mockMultiplexer.EXPECT().RemoveConn(gomock.Any())
		handler.close(testErr)
	})

	Context("handling packets", func() {
		It("handles packets for different packet handlers on the same packet conn", func() {
			connID1 := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			connID2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
			packetHandler1 := NewMockPacketHandler(mockCtrl)
			packetHandler2 := NewMockPacketHandler(mockCtrl)
			handledPacket1 := make(chan struct{})
			handledPacket2 := make(chan struct{})
			packetHandler1.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.header.DestConnectionID).To(Equal(connID1))
				close(handledPacket1)
			})
			packetHandler1.EXPECT().GetVersion()
			packetHandler1.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			packetHandler2.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.header.DestConnectionID).To(Equal(connID2))
				close(handledPacket2)
			})
			packetHandler2.EXPECT().GetVersion()
			packetHandler2.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			handler.Add(connID1, packetHandler1)
			handler.Add(connID2, packetHandler2)

			conn.dataToRead <- getPacket(connID1)
			conn.dataToRead <- getPacket(connID2)
			Eventually(handledPacket1).Should(BeClosed())
			Eventually(handledPacket2).Should(BeClosed())
		})

		It("drops unparseable packets", func() {
			err := handler.handlePacket(nil, []byte("invalid"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error parsing invariant header:"))
		})

		It("deletes nil session entries after a wait time", func() {
			handler.deleteClosedSessionsAfter = 10 * time.Millisecond
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			handler.Add(connID, NewMockPacketHandler(mockCtrl))
			handler.Remove(connID)
			Eventually(func() error {
				return handler.handlePacket(nil, getPacket(connID))
			}).Should(MatchError("received a packet with an unexpected connection ID 0x0102030405060708"))
		})

		It("ignores packets arriving late for closed sessions", func() {
			handler.deleteClosedSessionsAfter = time.Hour
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			handler.Add(connID, NewMockPacketHandler(mockCtrl))
			handler.Remove(connID)
			err := handler.handlePacket(nil, getPacket(connID))
			Expect(err).ToNot(HaveOccurred())
		})

		It("drops packets for unknown receivers", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			err := handler.handlePacket(nil, getPacket(connID))
			Expect(err).To(MatchError("received a packet with an unexpected connection ID 0x0102030405060708"))
		})

		It("errors on packets that are smaller than the Payload Length in the packet header", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			packetHandler := NewMockPacketHandler(mockCtrl)
			handled := make(chan struct{})
			packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				close(handled)
			})
			packetHandler.EXPECT().GetVersion().Return(versionIETFFrames)
			packetHandler.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			handler.Add(connID, packetHandler)
			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				PayloadLen:       1000,
				DestConnectionID: connID,
				PacketNumberLen:  protocol.PacketNumberLen1,
				Version:          versionIETFFrames,
			}
			buf := &bytes.Buffer{}
			Expect(hdr.Write(buf, protocol.PerspectiveServer, versionIETFFrames)).To(Succeed())
			buf.Write(bytes.Repeat([]byte{0}, 500))

			err := handler.handlePacket(nil, buf.Bytes())
			Expect(err).To(MatchError("packet payload (500 bytes) is smaller than the expected payload length (1000 bytes)"))
		})

		It("cuts packets at the Payload Length", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			packetHandler := NewMockPacketHandler(mockCtrl)
			packetHandler.EXPECT().GetVersion().Return(versionIETFFrames)
			packetHandler.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			handler.Add(connID, packetHandler)
			packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.data).To(HaveLen(456))
			})

			hdr := &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				PayloadLen:       456,
				DestConnectionID: connID,
				PacketNumberLen:  protocol.PacketNumberLen1,
				Version:          versionIETFFrames,
			}
			buf := &bytes.Buffer{}
			Expect(hdr.Write(buf, protocol.PerspectiveServer, versionIETFFrames)).To(Succeed())
			buf.Write(bytes.Repeat([]byte{0}, 500))
			err := handler.handlePacket(nil, buf.Bytes())
			Expect(err).ToNot(HaveOccurred())
		})

		It("closes the packet handlers when reading from the conn fails", func() {
			done := make(chan struct{})
			packetHandler := NewMockPacketHandler(mockCtrl)
			packetHandler.EXPECT().destroy(gomock.Any()).Do(func(e error) {
				Expect(e).To(HaveOccurred())
				close(done)
			})
			handler.Add(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}, packetHandler)
			conn.Close()
			Eventually(done).Should(BeClosed())
		})

		Context("coalesced packets", func() {
			It("errors on packets that are smaller than the length in the packet header, for too small packet number", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				data := getPacketWithLength(connID, 3) // gets a packet with a 2 byte packet number
				_, err := handler.parsePacket(nil, nil, data)
				Expect(err).To(MatchError("packet length (2 bytes) is smaller than the expected length (3 bytes)"))
			})

			It("errors on packets that are smaller than the length in the packet header, for too small payload", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				data := append(getPacketWithLength(connID, 1000), make([]byte, 500-2 /* for packet number length */)...)
				_, err := handler.parsePacket(nil, nil, data)
				Expect(err).To(MatchError("packet length (500 bytes) is smaller than the expected length (1000 bytes)"))
			})

			It("cuts packets to the right length", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				data := append(getPacketWithLength(connID, 456), make([]byte, 1000)...)
				packetHandler := NewMockPacketHandler(mockCtrl)
				packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
					Expect(p.data).To(HaveLen(456 + int(p.hdr.ParsedLen())))
				})
				handler.Add(connID, packetHandler)
				handler.handlePacket(nil, nil, data)
			})

			It("handles coalesced packets", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				packetHandler := NewMockPacketHandler(mockCtrl)
				handledPackets := make(chan *receivedPacket, 3)
				packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
					handledPackets <- p
				}).Times(3)
				handler.Add(connID, packetHandler)

				buffer := getPacketBuffer()
				packet := buffer.Slice[:0]
				packet = append(packet, append(getPacketWithLength(connID, 10), make([]byte, 10-2 /* packet number len */)...)...)
				packet = append(packet, append(getPacketWithLength(connID, 20), make([]byte, 20-2 /* packet number len */)...)...)
				packet = append(packet, append(getPacketWithLength(connID, 30), make([]byte, 30-2 /* packet number len */)...)...)
				conn.dataToRead <- packet

				now := time.Now()
				for i := 1; i <= 3; i++ {
					var p *receivedPacket
					Eventually(handledPackets).Should(Receive(&p))
					Expect(p.hdr.DestConnectionID).To(Equal(connID))
					Expect(p.hdr.Length).To(BeEquivalentTo(10 * i))
					Expect(p.data).To(HaveLen(int(p.hdr.ParsedLen() + p.hdr.Length)))
					Expect(p.rcvTime).To(BeTemporally("~", now, scaleDuration(20*time.Millisecond)))
					Expect(p.buffer.refCount).To(Equal(3))
				}
			})

			It("ignores coalesced packet parts if the connection IDs don't match", func() {
				connID1 := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				connID2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}

				buffer := getPacketBuffer()
				packet := buffer.Slice[:0]
				// var packet []byte
				packet = append(packet, getPacket(connID1)...)
				packet = append(packet, getPacket(connID2)...)

				packets, err := handler.parsePacket(&net.UDPAddr{}, buffer, packet)
				Expect(err).To(MatchError("coalesced packet has different destination connection ID: 0x0807060504030201, expected 0x0102030405060708"))
				Expect(packets).To(HaveLen(1))
				Expect(packets[0].hdr.DestConnectionID).To(Equal(connID1))
				Expect(packets[0].buffer.refCount).To(Equal(1))
			})
		})
	})

	Context("stateless reset handling", func() {
		It("handles packets for connections added with a reset token", func() {
			packetHandler := NewMockPacketHandler(mockCtrl)
			connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, packetHandler, token)
			// first send a normal packet
			handledPacket := make(chan struct{})
			packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.hdr.DestConnectionID).To(Equal(connID))
				close(handledPacket)
			})
			conn.dataToRead <- getPacket(connID)
			Eventually(handledPacket).Should(BeClosed())
		})

		It("handles stateless resets", func() {
			packetHandler := NewMockPacketHandler(mockCtrl)
			connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, packetHandler, token)
			packet := append([]byte{0x40} /* short header packet */, make([]byte, 50)...)
			packet = append(packet, token[:]...)
			destroyed := make(chan struct{})
			packetHandler.EXPECT().destroy(errors.New("received a stateless reset")).Do(func(error) {
				close(destroyed)
			})
			conn.dataToRead <- packet
			Eventually(destroyed).Should(BeClosed())
		})

		It("detects a stateless that is coalesced with another packet", func() {
			packetHandler := NewMockPacketHandler(mockCtrl)
			connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, packetHandler, token)
			fakeConnID := protocol.ConnectionID{1, 2, 3, 4, 5}
			packet := getPacket(fakeConnID)
			reset := append([]byte{0x40} /* short header packet */, fakeConnID...)
			reset = append(reset, make([]byte, 50)...) // add some "random" data
			reset = append(reset, token[:]...)
			destroyed := make(chan struct{})
			packetHandler.EXPECT().destroy(errors.New("received a stateless reset")).Do(func(error) {
				close(destroyed)
			})
			conn.dataToRead <- append(packet, reset...)
			Eventually(destroyed).Should(BeClosed())
		})

		It("deletes reset tokens when the session is retired", func() {
			handler.deleteRetiredSessionsAfter = scaleDuration(10 * time.Millisecond)
			connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0x42}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, NewMockPacketHandler(mockCtrl), token)
			handler.Retire(connID)
			time.Sleep(scaleDuration(30 * time.Millisecond))
			handler.handlePacket(nil, nil, getPacket(connID))
			// don't EXPECT any calls to handlePacket of the MockPacketHandler
			packet := append([]byte{0x40, 0xde, 0xca, 0xfb, 0xad, 0x99} /* short header packet */, make([]byte, 50)...)
			packet = append(packet, token[:]...)
			handler.handlePacket(nil, nil, packet)
			// don't EXPECT any calls to handlePacket of the MockPacketHandler
			Expect(handler.resetTokens).To(BeEmpty())
		})
	})

	Context("running a server", func() {
		It("adds a server", func() {
			connID := protocol.ConnectionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
			p := getPacket(connID)
			server := NewMockUnknownPacketHandler(mockCtrl)
			server.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.header.DestConnectionID).To(Equal(connID))
			})
			handler.SetServer(server)
			Expect(handler.handlePacket(nil, p)).To(Succeed())
		})

		It("closes all server sessions", func() {
			clientSess := NewMockPacketHandler(mockCtrl)
			clientSess.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			serverSess := NewMockPacketHandler(mockCtrl)
			serverSess.EXPECT().GetPerspective().Return(protocol.PerspectiveServer)
			serverSess.EXPECT().Close()

			handler.Add(protocol.ConnectionID{1, 1, 1, 1}, clientSess)
			handler.Add(protocol.ConnectionID{2, 2, 2, 2}, serverSess)
			handler.CloseServer()
		})

		It("stops handling packets with unknown connection IDs after the server is closed", func() {
			connID := protocol.ConnectionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
			p := getPacket(connID)
			server := NewMockUnknownPacketHandler(mockCtrl)
			handler.SetServer(server)
			handler.CloseServer()
			Expect(handler.handlePacket(nil, p)).To(MatchError("received a packet with an unexpected connection ID 0x1122334455667788"))
		})
	})
})
