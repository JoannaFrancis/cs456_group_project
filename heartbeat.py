#	Push-Based Heartbeat (Unidirectional Notification): The critical process autonomously emits a small datagram (a "beat") at a regular, 
#fixed period T to the monitor. The monitor maintains an expiring countdown timer or sliding window. Each arrival of a valid beat resets the timer. 
#If N consecutive periods elapse without a beat, the monitor flags a timeout and raises a fault alert. 
