pub const FixtureKind = enum {
    state_transition,
    fork_choice,
    // verify_signatures is temporarily disabled due to XMSS config mismatch
    // between Python test config (424-byte signatures) and Rust production config (3112-byte signatures)
    // verify_signatures,

    pub fn runnerModule(self: FixtureKind) []const u8 {
        return switch (self) {
            .state_transition => "state_transition",
            .fork_choice => "fork_choice",
            // .verify_signatures => "verify_signatures",
        };
    }

    pub fn handlerSubdir(self: FixtureKind) []const u8 {
        return switch (self) {
            .state_transition => "state_transition",
            .fork_choice => "fc",
            // .verify_signatures => "verify_signatures",
        };
    }
};

pub const all = [_]FixtureKind{ .state_transition, .fork_choice };
