/*
This application was written to do nothing.
It simply runs in the background to ensure that the credentials dropped 
stay in memory.
*/

package main

import "time"

func main() {
	for {
		// Sleep in a perpetual loop.
		time.Sleep(3600 * time.Second)
	}
}