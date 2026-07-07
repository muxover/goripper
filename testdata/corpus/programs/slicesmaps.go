package main

import "fmt"

//go:noinline
func sumSlice(xs []int) int {
	total := 0
	for _, v := range xs {
		total += v
	}
	return total
}

//go:noinline
func countWords(words []string) map[string]int {
	counts := make(map[string]int)
	for _, w := range words {
		counts[w]++
	}
	return counts
}

func main() {
	fmt.Println(sumSlice([]int{1, 2, 3}))
	fmt.Println(countWords([]string{"a", "b", "a"}))
}
