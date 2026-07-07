package main

import "fmt"

//go:noinline
func mustPositive(n int) (result int) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	if n < 0 {
		panic("negative")
	}
	return n * 2
}

func main() {
	fmt.Println(mustPositive(5))
	fmt.Println(mustPositive(-1))
}
