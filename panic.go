package main

import "fmt"

// PanicToErr converts a panic to an error, the resultant error
// being the string representation of the panic prefixed by the
// errString.
// This error is written to the pointer provided in err.
// This pointer, will be, for example, the named return of a
// function, and hence this function can dynamically modify the
// return of a function if this function is deferred to run after it.
func panicToErr(errString string, err *error) {
	panicData := recover()
	if panicData != nil {
		if panicErr, ok := panicData.(error); ok {
			*err = fmt.Errorf(errString+": %w", panicErr)
		} else {
			*err = fmt.Errorf(errString+": %v", panicData)
		}
	}
}
