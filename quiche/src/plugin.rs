use std::convert::TryInto;

use pluginop::api::CTPError;
use pluginop::api::ConnectionToPlugin;
use pluginop::api::ToPluginizableConnection;
use pluginop::common::quic;
use pluginop::common::quic::ACKFrame;
use pluginop::common::quic::ConnectionCloseFrame;
use pluginop::common::quic::ConnectionField;
use pluginop::common::quic::CryptoFrame;
use pluginop::common::quic::DataBlockedFrame;
use pluginop::common::quic::ExtensionFrame;
use pluginop::common::quic::HandshakeDoneFrame;
use pluginop::common::quic::HeaderExt;
use pluginop::common::quic::MaxDataFrame;
use pluginop::common::quic::MaxStreamDataFrame;
use pluginop::common::quic::MaxStreamsFrame;
use pluginop::common::quic::PaddingFrame;
use pluginop::common::quic::PathChallengeFrame;
use pluginop::common::quic::PathResponseFrame;
use pluginop::common::quic::PingFrame;
use pluginop::common::quic::RecoveryField;
use pluginop::common::quic::ResetStreamFrame;
use pluginop::common::quic::RetireConnectionIdFrame;
use pluginop::common::quic::StopSendingFrame;
use pluginop::common::quic::StreamDataBlockedFrame;
use pluginop::common::quic::StreamFrame;
use pluginop::common::quic::StreamsBlockedFrame;
use pluginop::common::Bytes;
use pluginop::common::PluginVal;
use pluginop::FromWithPH;
use pluginop::ParentReferencer;
use pluginop::PluginizableConnection;
use pluginop::TryFromWithPH;

use crate::frame;
use crate::packet;

impl pluginop::api::ConnectionToPlugin for crate::Connection {
    fn get_recovery(
        &self, _: &mut [u8], _: RecoveryField,
    ) -> bincode::Result<()> {
        todo!("find the right recovery")
    }

    fn set_recovery(&mut self, _: RecoveryField, _: &[u8]) {
        todo!("find the right recovery")
    }

    fn get_connection(
        &self, field: ConnectionField, w: &mut [u8],
    ) -> bincode::Result<()> {
        let pv: PluginVal = match field {
            ConnectionField::MaxTxData => self.max_tx_data.into(),
            _ => todo!(),
        };
        bincode::serialize_into(w, &pv)
    }

    fn set_connection(
        &mut self, field: ConnectionField, r: &[u8],
    ) -> std::result::Result<(), CTPError> {
        let pv: PluginVal =
            bincode::deserialize_from(r).map_err(|_| CTPError::SerializeError)?;
        match field {
            ConnectionField::MaxTxData =>
                self.max_tx_data = pv.try_into().map_err(|_| CTPError::BadType)?,
            _ => todo!(),
        };
        Ok(())
    }
}

impl ToPluginizableConnection<crate::Connection> for crate::Connection {
    fn set_pluginizable_connection(
        &mut self, pc: *mut PluginizableConnection<Self>,
    ) {
        self.pc = Some(ParentReferencer::new(pc));

        for (_, p) in self.paths.iter_mut() {
            p.recovery.set_pluginizable_connection(pc);
        }
    }

    fn get_pluginizable_connection(
        &mut self,
    ) -> Option<&mut PluginizableConnection<Self>> {
        self.pc.as_deref_mut()
    }
}

impl<CTP: ConnectionToPlugin> FromWithPH<frame::Frame, CTP> for PluginVal {
    fn from_with_ph(
        value: frame::Frame, _ph: &pluginop::handler::PluginHandler<CTP>,
    ) -> Self {
        let frame = match value {
            frame::Frame::Padding { len } =>
                quic::Frame::Padding(PaddingFrame { length: len as u64 }),

            frame::Frame::Ping => quic::Frame::Ping(PingFrame),

            frame::Frame::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                let mut ack_ranges = Vec::new();
                let ack_range_count = ranges.len() as u64 - 1;

                let mut ranges_iter = ranges.iter();
                let first_range = ranges_iter.next_back().unwrap();
                let largest_acknowledged = first_range.end - 1;
                let first_ack_range = largest_acknowledged - first_range.start;

                let mut smallest_ack = first_range.start;
                while let Some(r) = ranges_iter.next_back() {
                    let gap = smallest_ack - r.end - 1;
                    let ack_range_length = (r.end - 1) - r.start;

                    ack_ranges.push(quic::AckRange {
                        gap,
                        ack_range_length,
                    });

                    smallest_ack = r.start;
                }
                let ecn_counts = ecn_counts.map(|e| quic::EcnCount {
                    ect0_count: e.ect0_count,
                    ect1_count: e.ect1_count,
                    ectce_count: e.ecn_ce_count,
                });

                #[allow(unreachable_code)]
                quic::Frame::ACK(ACKFrame {
                    largest_acknowledged,
                    ack_delay,
                    ack_range_count,
                    first_ack_range,
                    ecn_counts,
                    ack_ranges: todo!(),
                })
            },

            frame::Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => quic::Frame::ResetStream(ResetStreamFrame {
                stream_id,
                application_protocol_error_code: error_code,
                final_size,
            }),

            frame::Frame::StopSending {
                stream_id,
                error_code,
            } => quic::Frame::StopSending(StopSendingFrame {
                stream_id,
                application_protocol_error_code: error_code,
            }),

            #[allow(unreachable_code)]
            frame::Frame::Crypto { data } => quic::Frame::Crypto(CryptoFrame {
                offset: data.off(),
                length: data.len() as u64,
                crypto_data: todo!(),
            }),

            #[allow(unreachable_code)]
            frame::Frame::CryptoHeader { offset, length } =>
                quic::Frame::Crypto(CryptoFrame {
                    offset,
                    length: length as u64,
                    crypto_data: todo!(),
                }),

            frame::Frame::NewToken { .. } => todo!(),

            #[allow(unreachable_code)]
            frame::Frame::Stream { stream_id, data } =>
                quic::Frame::Stream(StreamFrame {
                    stream_id,
                    offset: Some(data.off()),
                    length: Some(data.len() as u64),
                    fin: data.fin(),
                    stream_data: todo!(),
                }),

            #[allow(unreachable_code)]
            frame::Frame::StreamHeader {
                stream_id,
                offset,
                length,
                fin,
            } => quic::Frame::Stream(StreamFrame {
                stream_id,
                offset: Some(offset),
                length: Some(length as u64),
                fin,
                stream_data: todo!(),
            }),

            frame::Frame::MaxData { max } =>
                quic::Frame::MaxData(MaxDataFrame { maximum_data: max }),

            frame::Frame::MaxStreamData { stream_id, max } =>
                quic::Frame::MaxStreamData(MaxStreamDataFrame {
                    stream_id,
                    maximum_stream_data: max,
                }),

            frame::Frame::MaxStreamsBidi { max } =>
                quic::Frame::MaxStreams(MaxStreamsFrame {
                    unidirectional: false,
                    maximum_streams: max,
                }),

            frame::Frame::MaxStreamsUni { max } =>
                quic::Frame::MaxStreams(MaxStreamsFrame {
                    unidirectional: true,
                    maximum_streams: max,
                }),

            frame::Frame::DataBlocked { limit } =>
                quic::Frame::DataBlocked(DataBlockedFrame {
                    maximum_data: limit,
                }),

            frame::Frame::StreamDataBlocked { stream_id, limit } =>
                quic::Frame::StreamDataBlocked(StreamDataBlockedFrame {
                    stream_id,
                    maximum_stream_data: limit,
                }),

            frame::Frame::StreamsBlockedBidi { limit } =>
                quic::Frame::StreamsBlocked(StreamsBlockedFrame {
                    unidirectional: false,
                    maximum_streams: limit,
                }),

            frame::Frame::StreamsBlockedUni { limit } =>
                quic::Frame::StreamsBlocked(StreamsBlockedFrame {
                    unidirectional: false,
                    maximum_streams: limit,
                }),

            #[allow(unreachable_code)]
            frame::Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                ..
            } => quic::Frame::NewConnectionId(quic::NewConnectionIdFrame {
                sequence_number: seq_num,
                retire_prior_to,
                length: conn_id.len() as u8,
                connection_id: todo!(),
                stateless_reset_token: todo!(),
            }),

            frame::Frame::RetireConnectionId { seq_num } =>
                quic::Frame::RetireConnectionId(RetireConnectionIdFrame {
                    sequence_number: seq_num,
                }),

            #[allow(unreachable_code)]
            frame::Frame::PathChallenge { .. } =>
                quic::Frame::PathChallenge(PathChallengeFrame { data: todo!() }),

            #[allow(unreachable_code)]
            frame::Frame::PathResponse { .. } =>
                quic::Frame::PathResponse(PathResponseFrame { data: todo!() }),

            #[allow(unreachable_code)]
            frame::Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => quic::Frame::ConnectionClose(ConnectionCloseFrame {
                error_code,
                frame_type: Some(frame_type),
                reason_phrase_length: reason.len() as u64,
                reason_phrase: todo!(),
            }),

            #[allow(unreachable_code)]
            frame::Frame::ApplicationClose { error_code, reason } =>
                quic::Frame::ConnectionClose(ConnectionCloseFrame {
                    error_code,
                    frame_type: None,
                    reason_phrase_length: reason.len() as u64,
                    reason_phrase: todo!(),
                }),

            frame::Frame::HandshakeDone =>
                quic::Frame::HandshakeDone(HandshakeDoneFrame),

            #[allow(unreachable_code)]
            frame::Frame::Datagram { .. } =>
                quic::Frame::Extension(ExtensionFrame {
                    frame_type: 0x30,
                    tag: todo!(),
                }),

            #[allow(unreachable_code)]
            frame::Frame::DatagramHeader { .. } =>
                quic::Frame::Extension(ExtensionFrame {
                    frame_type: 0x30,
                    tag: todo!(),
                }),

            frame::Frame::Extension { ty, tag } =>
                quic::Frame::Extension(ExtensionFrame {
                    frame_type: ty,
                    tag,
                }),
        };
        PluginVal::QUIC(quic::QVal::Frame(frame))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TryFromCoreQuicheError {
    BadFrame,
}

impl<CTP: ConnectionToPlugin> TryFromWithPH<PluginVal, CTP> for frame::Frame {
    type Error = TryFromCoreQuicheError;

    fn try_from_with_ph(
        value: PluginVal, _ph: &pluginop::handler::PluginHandler<CTP>,
    ) -> Result<Self, Self::Error> {
        let f = if let PluginVal::QUIC(quic::QVal::Frame(f)) = value {
            f
        } else {
            return Err(TryFromCoreQuicheError::BadFrame);
        };
        let quiche_frame = match f {
            quic::Frame::Padding(p) => frame::Frame::Padding {
                len: p.length as usize,
            },
            quic::Frame::Ping(_) => frame::Frame::Ping,
            quic::Frame::ACK(_) => todo!("ack"),
            quic::Frame::ResetStream(rs) => frame::Frame::ResetStream {
                stream_id: rs.stream_id,
                error_code: rs.application_protocol_error_code,
                final_size: rs.final_size,
            },
            quic::Frame::StopSending(ss) => frame::Frame::StopSending {
                stream_id: ss.stream_id,
                error_code: ss.application_protocol_error_code,
            },
            quic::Frame::Crypto(_) => todo!("crypto"),
            quic::Frame::NewToken(_) => todo!("new token"),
            quic::Frame::Stream(_) => todo!("stream"),
            quic::Frame::MaxData(md) => frame::Frame::MaxData {
                max: md.maximum_data,
            },
            quic::Frame::MaxStreamData(msd) => frame::Frame::MaxStreamData {
                stream_id: msd.stream_id,
                max: msd.maximum_stream_data,
            },
            quic::Frame::MaxStreams(ms) =>
                if ms.unidirectional {
                    frame::Frame::MaxStreamsUni {
                        max: ms.maximum_streams,
                    }
                } else {
                    frame::Frame::MaxStreamsBidi {
                        max: ms.maximum_streams,
                    }
                },
            quic::Frame::DataBlocked(db) => frame::Frame::DataBlocked {
                limit: db.maximum_data,
            },
            quic::Frame::StreamDataBlocked(sdb) =>
                frame::Frame::StreamDataBlocked {
                    stream_id: sdb.stream_id,
                    limit: sdb.maximum_stream_data,
                },
            quic::Frame::StreamsBlocked(sb) =>
                if sb.unidirectional {
                    frame::Frame::StreamsBlockedUni {
                        limit: sb.maximum_streams,
                    }
                } else {
                    frame::Frame::StreamsBlockedBidi {
                        limit: sb.maximum_streams,
                    }
                },
            quic::Frame::NewConnectionId(_) => todo!("new cid"),
            quic::Frame::RetireConnectionId(rc) =>
                frame::Frame::RetireConnectionId {
                    seq_num: rc.sequence_number,
                },
            quic::Frame::PathChallenge(pc) => frame::Frame::PathChallenge {
                data: pc.data.to_be_bytes(),
            },
            quic::Frame::PathResponse(pr) => frame::Frame::PathResponse {
                data: pr.data.to_be_bytes(),
            },
            quic::Frame::ConnectionClose(_) => todo!("connection close"),
            quic::Frame::HandshakeDone(_) => frame::Frame::HandshakeDone,
            quic::Frame::Extension(e) => frame::Frame::Extension {
                ty: e.frame_type,
                tag: e.tag,
            },
            f => todo!("unknown frame {f:?}"),
        };
        Ok(quiche_frame)
    }
}

// impl From<frame::Frame> for PluginVal {
//     fn from(value: frame::Frame) -> Self {
//         PluginVal::QUIC(quic::QVal::Frame(value.into()))
//     }
// }

impl<CTP: ConnectionToPlugin> FromWithPH<packet::Header<'_>, CTP> for PluginVal {
    fn from_with_ph(
        h: packet::Header<'_>, _ph: &pluginop::handler::PluginHandler<CTP>,
    ) -> Self {
        // FIXME
        let dcid = Bytes {
            tag: 0,
            max_read_len: 0,
            max_write_len: 0,
        }; // h.dcid.to_vec()
        let hdr = match h.ty {
            crate::Type::VersionNegotiation => quic::Header {
                first: h.first_byte().unwrap_or(0),
                version: Some(0),
                destination_cid: dcid,    // TODO
                source_cid: None,         // TODO
                supported_versions: None, // TODO
                ext: Some(HeaderExt {
                    packet_number: Some(h.pkt_num),
                    packet_number_len: Some(h.pkt_num_len as u8),
                    token: None, // TODO
                    key_phase: Some(h.key_phase),
                }),
            },

            crate::Type::Short => quic::Header {
                first: h.first_byte().unwrap_or(0),
                version: None,
                destination_cid: dcid, // TODO
                source_cid: None,
                supported_versions: None,
                ext: Some(HeaderExt {
                    packet_number: Some(h.pkt_num),
                    packet_number_len: Some(h.pkt_num_len as u8),
                    token: None, // TODO
                    key_phase: Some(h.key_phase),
                }),
            },

            // Other are long headers.
            _ => quic::Header {
                first: h.first_byte().unwrap_or(0),
                version: Some(h.version),
                destination_cid: dcid, // TODO
                source_cid: None,      // TODO
                supported_versions: None,
                ext: Some(HeaderExt {
                    packet_number: Some(h.pkt_num),
                    packet_number_len: Some(h.pkt_num_len as u8),
                    token: None, // TODO
                    key_phase: Some(h.key_phase),
                }),
            },
        };
        PluginVal::QUIC(quic::QVal::Header(hdr))
    }
}

// impl From<packet::Header<'_>> for PluginVal {
//     fn from(value: packet::Header<'_>) -> Self {
//         PluginVal::QUIC(quic::QVal::Header(value.into()))
//     }
// }

impl<CTP: ConnectionToPlugin> FromWithPH<packet::Epoch, CTP> for PluginVal {
    fn from_with_ph(
        value: packet::Epoch, _: &pluginop::handler::PluginHandler<CTP>,
    ) -> Self {
        let pns = match value {
            packet::Epoch::Initial => quic::KPacketNumberSpace::Initial,
            packet::Epoch::Handshake => quic::KPacketNumberSpace::Handshake,
            packet::Epoch::Application =>
                quic::KPacketNumberSpace::ApplicationData,
        };
        PluginVal::QUIC(quic::QVal::PacketNumberSpace(pns))
    }
}

// impl From<packet::Epoch> for PluginVal {
//     fn from(value: packet::Epoch) -> Self {
//         PluginVal::QUIC(quic::QVal::PacketNumberSpace(value.into()))
//     }
// }

impl From<i64> for crate::Error {
    fn from(e: i64) -> Self {
        println!("Error value {e}");
        todo!()
    }
}

impl<CTP: ConnectionToPlugin> FromWithPH<packet::Type, CTP> for PluginVal {
    fn from_with_ph(
        value: packet::Type, _: &pluginop::handler::PluginHandler<CTP>,
    ) -> Self {
        let pkt_type = match value {
            crate::Type::Initial => quic::PacketType::Initial,
            crate::Type::Retry => quic::PacketType::Retry,
            crate::Type::Handshake => quic::PacketType::Handshake,
            crate::Type::ZeroRTT => quic::PacketType::ZeroRTT,
            crate::Type::VersionNegotiation =>
                quic::PacketType::VersionNegotiation,
            crate::Type::Short => quic::PacketType::Short,
        };
        PluginVal::QUIC(quic::QVal::PacketType(pkt_type))
    }
}
