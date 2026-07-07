package main

import (
	"errors"
	"fmt"
)

type shape interface {
	area() float64
}

type square struct {
	side float64
}

//go:noinline
func (s square) area() float64 {
	return s.side * s.side
}

//go:noinline
func totalArea(shapes []shape) float64 {
	var total float64
	for _, s := range shapes {
		total += s.area()
	}
	return total
}

//go:noinline
func safeDiv(a, b int) (int, error) {
	if b == 0 {
		return 0, errors.New("divide by zero")
	}
	return a / b, nil
}

func main() {
	fmt.Println(totalArea([]shape{square{2}, square{3}}))
	q, err := safeDiv(10, 0)
	fmt.Println(q, err)
}
