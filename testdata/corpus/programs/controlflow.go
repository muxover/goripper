package main

import "fmt"

//go:noinline
func classify(n int) string {
	if n < 0 {
		return "neg"
	} else if n == 0 {
		return "zero"
	}
	return "pos"
}

//go:noinline
func sumTo(n int) int {
	total := 0
	for i := 1; i <= n; i++ {
		total += i
	}
	return total
}

//go:noinline
func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	default:
		return "F"
	}
}

func main() {
	fmt.Println(classify(-3), sumTo(10), grade(85))
}
