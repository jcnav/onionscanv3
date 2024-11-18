package 
import (
        "regexp"                                                                                                              
        "strings"                                                                                                             
)                                                                                                                                                                                                                                                    
// IsOnion checks if the identifier is a valid .onion address                                                                
func IsOnion(identifier string) bool {                                                                                        
        // Check for minimum length and .onion suffix                                                                         
        if len(identifier) >= 22 && strings.HasSuffix(identifier, ".onion") {                                                 
                // Correct regular expression for v2 and v3 onion addresses                                                   
                matched, _ := regexp.MatchString(`^[a-z2-7]{16,56}\.onion$`, identifier)                                      
                return matched                                                                                                
        }                                                                                                                     
        return false                                                                                                          
} 
