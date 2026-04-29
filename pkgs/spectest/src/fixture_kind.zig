pub const FixtureKind = enum {
    state_transition,
    fork_choice,
    ssz,
    justifiability,
    verify_signatures,
    slot_clock,
    api_endpoint,
    networking_codec,

    pub fn runnerModule(self: FixtureKind) []const u8 {
        return switch (self) {
            .state_transition => "state_transition",
            .fork_choice => "fork_choice",
            .ssz => "ssz",
            .justifiability => "justifiability",
            .verify_signatures => "verify_signatures",
            .slot_clock => "slot_clock",
            .api_endpoint => "api_endpoint",
            .networking_codec => "networking_codec",
        };
    }

    pub fn handlerSubdir(self: FixtureKind) []const u8 {
        return switch (self) {
            .state_transition => "state_transition",
            .fork_choice => "fc",
            .ssz => "ssz",
            .justifiability => "justifiability",
            .verify_signatures => "verify_signatures",
            .slot_clock => "slot_clock",
            .api_endpoint => "api_endpoint",
            .networking_codec => "networking_codec",
        };
    }
};

pub const all = [_]FixtureKind{ .state_transition, .fork_choice, .ssz, .justifiability, .verify_signatures, .slot_clock, .api_endpoint, .networking_codec };
