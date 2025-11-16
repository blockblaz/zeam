pub const FixtureKind = enum {
    state_transition,
    fork_choice,

    pub fn runnerModule(self: FixtureKind) []const u8 {
        return switch (self) {
            .state_transition => "state_transition",
            .fork_choice => "fork_choice",
        };
    }

    pub fn handlerSubdir(self: FixtureKind) []const u8 {
        return switch (self) {
            .state_transition => "state_transition",
            .fork_choice => "fc",
        };
    }
};

pub const all = [_]FixtureKind{ .state_transition, .fork_choice };
