#!/bin/bash

# Comprehensive Apache Log Analyzer
# Analyzes apache_logs file with full requirements coverage

# Configuration
LOG_FILE="apache_logs"
OUTPUT_FILE="apache_analysis_$(date +%Y%m%d_%H%M%S).txt"
SAMPLE_SIZE=""  # Empty for full analysis, or set to number for sample

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then
    echo "Error: Log file '$LOG_FILE' not found!"
    echo "Please download the file first using:"
    echo "wget https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/apache_logs/apache_logs -O apache_logs"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print section headers
section() {
    echo -e "\n${PURPLE}===== $1 =====${NC}" | tee -a "$OUTPUT_FILE"
}

# Function to print metrics
metric() {
    printf "%-40s: ${GREEN}%s${NC}\n" "$1" "$2" | tee -a "$OUTPUT_FILE"
}

# Create sample if needed
if [ -n "$SAMPLE_SIZE" ]; then
    head -n $SAMPLE_SIZE "$LOG_FILE" > "$LOG_FILE.sample"
    LOG_FILE="$LOG_FILE.sample"
    echo -e "${YELLOW}Analyzing sample of $SAMPLE_SIZE lines${NC}"
else
    echo -e "${CYAN}Analyzing complete log file${NC}"
fi

# Start analysis
{
    section "LOG FILE ANALYSIS REPORT"
    metric "Log file" "$LOG_FILE"
    metric "Total lines analyzed" "$(wc -l < "$LOG_FILE")"
    metric "First timestamp" "$(head -1 "$LOG_FILE" | awk '{print $4}' | tr -d '[]')"
    metric "Last timestamp" "$(tail -1 "$LOG_FILE" | awk '{print $4}' | tr -d '[]')"

    # 1. Request Counts
    section "1. REQUEST COUNTS"
    total_requests=$(wc -l < "$LOG_FILE")
    metric "Total requests" "$total_requests"
    metric "GET requests" "$(grep -c '"GET ' "$LOG_FILE")"
    metric "POST requests" "$(grep -c '"POST ' "$LOG_FILE")"
    metric "Other methods" "$(grep -vE '"GET |"POST ' "$LOG_FILE" | wc -l)"

    # 2. Unique IP Addresses
    section "2. UNIQUE IP ADDRESSES"
    unique_ips=$(awk '{print $1}' "$LOG_FILE" | sort -u | wc -l)
    metric "Total unique IP addresses" "$unique_ips"
    
    echo -e "\nTop 10 IPs with request counts:" | tee -a "$OUTPUT_FILE"
    awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -nr | head -10 | tee -a "$OUTPUT_FILE"
    
    echo -e "\nGET/POST counts per IP (Top 10):" | tee -a "$OUTPUT_FILE"
    awk '{
        ip = $1;
        method = $6;
        gsub(/"/, "", method);
        if (method == "GET" || method == "POST") {
            counts[ip][method]++;
        }
    }
    END {
        for (ip in counts) {
            printf "%15s: GET=%4d, POST=%4d\n", ip, counts[ip]["GET"]+0, counts[ip]["POST"]+0;
        }
    }' "$LOG_FILE" | sort -k3 -nr | head -10 | tee -a "$OUTPUT_FILE"

    # 3. Failure Requests
    section "3. FAILURE REQUESTS"
    failed_requests=$(awk '$9 ~ /^[45][0-9][0-9]$/ {count++} END {print count}' "$LOG_FILE")
    failure_percent=$(awk "BEGIN {printf \"%.2f\", $failed_requests/$total_requests*100}")
    metric "Failed requests (4xx & 5xx)" "$failed_requests ($failure_percent%)"
    
    echo -e "\nFailure status code breakdown:" | tee -a "$OUTPUT_FILE"
    awk '$9 ~ /^[45][0-9][0-9]$/ {print $9}' "$LOG_FILE" | sort | uniq -c | sort -nr | tee -a "$OUTPUT_FILE"

    # 4. Top User
    section "4. TOP USER"
    echo "Most active IP (total requests):" | tee -a "$OUTPUT_FILE"
    awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -nr | head -1 | tee -a "$OUTPUT_FILE"
    
    echo -e "\nMost active IP for GET requests:" | tee -a "$OUTPUT_FILE"
    awk '$6 ~ /"GET/ {print $1}' "$LOG_FILE" | sort | uniq -c | sort -nr | head -1 | tee -a "$OUTPUT_FILE"
    
    echo -e "\nMost active IP for POST requests:" | tee -a "$OUTPUT_FILE"
    awk '$6 ~ /"POST/ {print $1}' "$LOG_FILE" | sort | uniq -c | sort -nr | head -1 | tee -a "$OUTPUT_FILE"

    # 5. Daily Request Averages
    section "5. DAILY REQUEST AVERAGES"
    echo "Requests per day:" | tee -a "$OUTPUT_FILE"
    awk '{
        split($4, dateparts, /[/:]/);
        day = dateparts[1]"/"dateparts[2]"/"dateparts[3];
        days[day]++;
    }
    END {
        for (d in days) {
            print d, days[d];
        }
    }' "$LOG_FILE" | sort | tee -a "$OUTPUT_FILE"
    
    total_days=$(awk '{
        split($4, dateparts, /[/:]/);
        day = dateparts[1]"/"dateparts[2]"/"dateparts[3];
        days[day]++;
    }
    END {
        print length(days);
    }' "$LOG_FILE")
    
    avg_daily=$(awk "BEGIN {printf \"%.1f\", $total_requests/$total_days}")
    metric "Average requests per day" "$avg_daily"

    # 6. Failure Analysis
    section "6. FAILURE ANALYSIS"
    echo "Days with most failures (Top 5):" | tee -a "$OUTPUT_FILE"
    awk '$9 ~ /^[45][0-9][0-9]$/ {
        split($4, dateparts, /[/:]/);
        day = dateparts[1]"/"dateparts[2]"/"dateparts[3];
        fails[day]++;
    }
    END {
        for (d in fails) {
            print d, fails[d];
        }
    }' "$LOG_FILE" | sort -k2 -nr | head -5 | tee -a "$OUTPUT_FILE"

    # Additional Analysis
    section "ADDITIONAL ANALYSIS"

    # Request by Hour
    echo -e "\nRequests by hour (all days):" | tee -a "$OUTPUT_FILE"
    awk '{
        split($4, timeparts, ":");
        hour = timeparts[2];
        hours[hour]++;
    }
    END {
        for (h = 0; h < 24; h++) {
            hh = sprintf("%02d", h);
            printf "%2s:00-%2s:59: %4d requests\n", hh, hh, hours[hh]+0;
        }
    }' "$LOG_FILE" | tee -a "$OUTPUT_FILE"

    # Request Trends
    echo -e "\nBusiest hours (Top 5):" | tee -a "$OUTPUT_FILE"
    awk '{
        split($4, timeparts, ":");
        hour = timeparts[2];
        hours[hour]++;
    }
    END {
        for (h in hours) {
            printf "%s %d\n", h, hours[h];
        }
    }' "$LOG_FILE" | sort -k2 -nr | head -5 | tee -a "$OUTPUT_FILE"

    # Status Codes Breakdown
    echo -e "\nDetailed status code breakdown:" | tee -a "$OUTPUT_FILE"
    awk '{codes[$9]++} END {for (code in codes) {print code, codes[code]}}' "$LOG_FILE" | sort -n | tee -a "$OUTPUT_FILE"

    # Patterns in Failure Requests
    echo -e "\nFailure requests by hour (Top 5):" | tee -a "$OUTPUT_FILE"
    awk '$9 ~ /^[45][0-9][0-9]$/ {
        split($4, timeparts, ":");
        hour = timeparts[2];
        fails[hour]++;
    }
    END {
        for (h in fails) {
            printf "%2s:00-%2s:59: %3d failures\n", h, h, fails[h];
        }
    }' "$LOG_FILE" | sort -k3 -nr | head -5 | tee -a "$OUTPUT_FILE"

    # Analysis Suggestions
    section "ANALYSIS SUGGESTIONS"
    echo "1. Failure Reduction:" | tee -a "$OUTPUT_FILE"
    echo "   - Investigate most common error codes (shown above)" | tee -a "$OUTPUT_FILE"
    echo "   - Check the days/hours with highest failure rates for patterns" | tee -a "$OUTPUT_FILE"
    echo "   - Review URLs returning errors for possible fixes" | tee -a "$OUTPUT_FILE"
    
    echo -e "\n2. Performance Optimization:" | tee -a "$OUTPUT_FILE"
    echo "   - Scale resources during peak hours (identified above)" | tee -a "$OUTPUT_FILE"
    echo "   - Implement caching for frequently accessed resources" | tee -a "$OUTPUT_FILE"
    echo "   - Optimize endpoints with many POST requests" | tee -a "$OUTPUT_FILE"
    
    echo -e "\n3. Security Considerations:" | tee -a "$OUTPUT_FILE"
    echo "   - Investigate IPs with many failed requests" | tee -a "$OUTPUT_FILE"
    echo "   - Monitor suspicious activity patterns" | tee -a "$OUTPUT_FILE"
    echo "   - Check for brute force attempts on POST endpoints" | tee -a "$OUTPUT_FILE"
    
    echo -e "\n4. General Improvements:" | tee -a "$OUTPUT_FILE"
    echo "   - Analyze traffic patterns to plan maintenance windows" | tee -a "$OUTPUT_FILE"
    echo "   - Implement monitoring for identified peak times" | tee -a "$OUTPUT_FILE"
    echo "   - Consider rate limiting for abusive IPs" | tee -a "$OUTPUT_FILE"

} | tee "$OUTPUT_FILE"

echo -e "\n${GREEN}Analysis complete. Full report saved to ${YELLOW}$OUTPUT_FILE${NC}"
