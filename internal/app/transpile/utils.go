package transpile

func pointer[T any](d T) *T {
	return &d
}
