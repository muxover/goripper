package main

import "fmt"

type point struct {
	x, y int
}

//go:noinline
func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

//go:noinline
func (p point) manhattan() int {
	return abs(p.x) + abs(p.y)
}

//go:noinline
func makePoint(x, y int) point {
	return point{x: x, y: y}
}

func main() {
	p := makePoint(3, -4)
	fmt.Println(p.manhattan())
}
