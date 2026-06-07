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

// slot_clock + networking_codec are intentionally SKIPPED from generation: a spec
// testing-framework refactor restructured their fixtures (the flat `codecName`+`input`
// pair became a single `codec` discriminated union). They are peripheral (no consensus
// relevance), so we skip them rather than rewrite their runners. Re-add here once the
// runners are adapted to the new fixture shape.
pub const all = [_]FixtureKind{ .state_transition, .fork_choice, .ssz, .justifiability, .verify_signatures, .api_endpoint };
