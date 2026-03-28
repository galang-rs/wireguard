// Package optional provides a generic Optional/Maybe type.
package optional

// Value is a generic optional value.
type Value[T any] struct {
	value T
	valid bool
}

// Some creates a Value containing v.
func Some[T any](v T) Value[T] {
	return Value[T]{value: v, valid: true}
}

// None creates an empty Value.
func None[T any]() Value[T] {
	return Value[T]{}
}

// IsNone returns true if the value is not set.
func (o Value[T]) IsNone() bool { return !o.valid }

// IsSome returns true if the value is set.
func (o Value[T]) IsSome() bool { return o.valid }

// Unwrap returns the value. Panics if IsNone().
func (o Value[T]) Unwrap() T {
	if !o.valid {
		panic("optional: unwrap on None value")
	}
	return o.value
}

// UnwrapOr returns the value if set, or the fallback.
func (o Value[T]) UnwrapOr(fallback T) T {
	if !o.valid {
		return fallback
	}
	return o.value
}
