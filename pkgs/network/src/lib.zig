const interfaceFactory = @import("./interface.zig");
pub const GossipSub = interfaceFactory.GossipSub;
pub const ReqResp = interfaceFactory.ReqResp;
pub const PeerEvents = interfaceFactory.PeerEvents;
pub const NetworkInterface = interfaceFactory.NetworkInterface;
pub const OnGossipCbHandler = interfaceFactory.OnGossipCbHandler;
pub const GossipEncoding = interfaceFactory.GossipEncoding;
pub const LeanNetworkTopic = interfaceFactory.LeanNetworkTopic;
pub const GossipTopicKind = interfaceFactory.GossipTopicKind;
pub const GossipTopic = interfaceFactory.GossipTopic;
pub const AttestationGossip = interfaceFactory.AttestationGossip;
pub const GossipMessage = interfaceFactory.GossipMessage;
pub const LeanSupportedProtocol = interfaceFactory.LeanSupportedProtocol;
pub const ReqRespRequest = interfaceFactory.ReqRespRequest;
pub const ReqRespResponse = interfaceFactory.ReqRespResponse;
pub const ReqRespResponseEvent = interfaceFactory.ReqRespResponseEvent;
pub const ReqRespResponseError = interfaceFactory.ReqRespResponseError;
pub const ReqRespRequestCallback = interfaceFactory.ReqRespRequestCallback;
pub const OnPeerConnectedCbType = interfaceFactory.OnPeerConnectedCbType;
pub const OnPeerDisconnectedCbType = interfaceFactory.OnPeerDisconnectedCbType;
pub const OnPeerConnectionFailedCbType = interfaceFactory.OnPeerConnectionFailedCbType;
pub const OnPeerEventCbHandler = interfaceFactory.OnPeerEventCbHandler;
pub const PeerEventHandler = interfaceFactory.PeerEventHandler;
pub const PeerDirection = interfaceFactory.PeerDirection;
pub const ConnectionResult = interfaceFactory.ConnectionResult;
pub const DisconnectionReason = interfaceFactory.DisconnectionReason;
pub const GenericGossipHandler = interfaceFactory.GenericGossipHandler;
pub const ReqRespServerStream = interfaceFactory.ReqRespServerStream;
pub const OnReqRespResponseCbHandler = interfaceFactory.OnReqRespResponseCbHandler;
pub const OnReqRespRequestCbHandler = interfaceFactory.OnReqRespRequestCbHandler;

const mockFactory = @import("./mock.zig");
pub const Mock = mockFactory.Mock;

const node_registryFactory = @import("./node_registry.zig");
pub const NodeNameRegistry = node_registryFactory.NodeNameRegistry;

/// Pure-Zig libp2p path, on top of `zig-libp2p` v0.1.3 (gossipsub on the
/// wire + QuicRuntime + libp2p_tls_cert). Replaces the legacy `EthLibp2p`
/// + `rust/libp2p-glue/` crate, which were deleted in this commit.
pub const ethlibp2p = @import("./ethlibp2p.zig");
pub const EthLibp2p = ethlibp2p.EthLibp2p;
pub const EthLibp2pParams = ethlibp2p.EthLibp2pParams;

pub const gossip_codec = @import("./gossip_codec.zig");

test "get tests" {
    @import("std").testing.refAllDecls(@This());
}
