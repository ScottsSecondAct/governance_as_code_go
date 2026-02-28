package governance

// When returns a Policy that applies wrapped only when predicate(ctx) is true.
// When the predicate is false, the policy abstains (returns nil).
// Inherits Name, Version, Author, and Priority from wrapped.
func When(predicate func(RequestContext) bool, wrapped Policy) Policy {
	return Policy{
		Name:        wrapped.Name,
		Version:     wrapped.Version,
		Author:      wrapped.Author,
		Priority:    wrapped.Priority,
		Description: "When(" + wrapped.Name + "): conditional guard",
		Evaluate: func(ctx RequestContext) *PolicyDecision {
			if !predicate(ctx) {
				return nil
			}
			return wrapped.Evaluate(ctx)
		},
	}
}

// InEnvironment returns a predicate that is true when ctx.Environment matches
// any of the provided environment names.
func InEnvironment(envs ...string) func(RequestContext) bool {
	set := make(map[string]struct{}, len(envs))
	for _, e := range envs {
		set[e] = struct{}{}
	}
	return func(ctx RequestContext) bool {
		_, ok := set[ctx.Environment]
		return ok
	}
}

// ForResourceType returns a predicate that is true when ctx.Resource.Type matches
// any of the provided types.
func ForResourceType(types ...string) func(RequestContext) bool {
	set := make(map[string]struct{}, len(types))
	for _, t := range types {
		set[t] = struct{}{}
	}
	return func(ctx RequestContext) bool {
		_, ok := set[ctx.Resource.Type]
		return ok
	}
}

// ForRole returns a predicate that is true when ctx.Principal.Role matches
// any of the provided roles.
func ForRole(roles ...string) func(RequestContext) bool {
	set := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		set[r] = struct{}{}
	}
	return func(ctx RequestContext) bool {
		_, ok := set[ctx.Principal.Role]
		return ok
	}
}
