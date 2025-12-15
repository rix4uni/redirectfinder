package banner

import (
	"fmt"
)

// prints the version message
const version = "v0.0.1"

func PrintVersion() {
	fmt.Printf("Current redirectfinder version %s\n", version)
}

// Prints the Colorful banner
func PrintBanner() {
	banner := `
                    __ _                    __   ____ _             __           
   _____ ___   ____/ /(_)_____ ___   _____ / /_ / __/(_)____   ____/ /___   _____
  / ___// _ \ / __  // // ___// _ \ / ___// __// /_ / // __ \ / __  // _ \ / ___/
 / /   /  __// /_/ // // /   /  __// /__ / /_ / __// // / / // /_/ //  __// /    
/_/    \___/ \__,_//_//_/    \___/ \___/ \__//_/  /_//_/ /_/ \__,_/ \___//_/
`
	fmt.Printf("%s\n%65s\n\n", banner, "Current redirectfinder version "+version)
}

