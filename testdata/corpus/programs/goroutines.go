package main

import (
	"fmt"
	"sync"
)

//go:noinline
func parallelSum(nums []int) int {
	var wg sync.WaitGroup
	results := make(chan int, len(nums))
	for _, n := range nums {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			results <- v * v
		}(n)
	}
	wg.Wait()
	close(results)
	total := 0
	for r := range results {
		total += r
	}
	return total
}

func main() {
	fmt.Println(parallelSum([]int{1, 2, 3, 4}))
}
