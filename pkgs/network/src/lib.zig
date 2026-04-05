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

const ethp2pDiscoveryFactory = @import("./ethp2p_discovery.zig");
pub const EthP2PDiscovery = ethp2pDiscoveryFactory.EthP2PDiscovery;
pub const EthP2PDiscoveryParams = ethp2pDiscoveryFactory.EthP2PDiscoveryParams;
pub const DiscoveryBootstrapEntry = ethp2pDiscoveryFactory.DiscoveryBootstrapEntry;
pub const nodeIdFromCompressedPubkey = ethp2pDiscoveryFactory.nodeIdFromCompressedPubkey;

const ethp2pNetworkFactory = @import("./ethp2p_network.zig");
pub const EthP2PNetwork = ethp2pNetworkFactory.EthP2PNetwork;
pub const EthP2PNetworkParams = ethp2pNetworkFactory.EthP2PNetworkParams;

const node_registryFactory = @import("./node_registry.zig");
pub const NodeNameRegistry = node_registryFactory.NodeNameRegistry;

test "get tests" {
    @import("std").testing.refAllDeclsRecursive(@This());
}
