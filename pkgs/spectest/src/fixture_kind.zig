pub const FixtureKind = enum {
    state_transition,
    fork_choice,
    ssz,
    justifiability,
    verify_signatures,

    pub fn runnerModule(self: FixtureKind) []const u8 {
        return switch (self) {
            .state_transition => "state_transition",
            .fork_choice => "fork_choice",
            .ssz => "ssz",
            .justifiability => "justifiability",
            .verify_signatures => "verify_signatures",
        };
    }

    pub fn handlerSubdir(self: FixtureKind) []const u8 {
        return switch (self) {
            .state_transition => "state_transition",
            .fork_choice => "fc",
            .ssz => "ssz",
            .justifiability => "justifiability",
            .verify_signatures => "verify_signatures",
        };
    }
};

pub const all = [_]FixtureKind{ .state_transition, .fork_choice, .ssz, .justifiability, .verify_signatures };
