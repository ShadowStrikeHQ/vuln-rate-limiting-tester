import argparse
import logging
import requests
import time
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RateLimitTester:
    """
    Tests if rate limiting is implemented correctly by sending multiple requests
    in a short period and analyzing the responses.
    """

    def __init__(self, url, requests_per_second=10, max_requests=50, timeout=5, user_agent=None):
        """
        Initializes the RateLimitTester.

        Args:
            url (str): The URL to test.
            requests_per_second (int): Number of requests to send per second.
            max_requests (int): Maximum number of requests to send in total.
            timeout (int): Timeout for each request in seconds.
            user_agent (str): User-Agent string to use for the requests.
        """
        self.url = url
        self.requests_per_second = requests_per_second
        self.max_requests = max_requests
        self.timeout = timeout
        self.user_agent = user_agent if user_agent else "vuln-Rate-Limiting-Tester/1.0" # Default User-Agent
        self.session = requests.Session() # Use a session for connection pooling
        self.session.headers.update({"User-Agent": self.user_agent})


    def send_request(self):
        """
        Sends a single request to the target URL.

        Returns:
            requests.Response: The response object.  None if an exception occurred.
        """
        try:
            response = self.session.get(self.url, timeout=self.timeout)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            return None

    def analyze_response(self, response):
        """
        Analyzes the response for rate limiting headers and status codes.

        Args:
            response (requests.Response): The response object.

        Returns:
            dict: A dictionary containing rate limiting information or None if
                  the response is invalid.
        """
        if not response:
            return None

        rate_limit_info = {}
        headers = response.headers

        # Common rate limiting headers
        rate_limit_info['status_code'] = response.status_code
        rate_limit_info['x_ratelimit_limit'] = headers.get('X-RateLimit-Limit')
        rate_limit_info['x_ratelimit_remaining'] = headers.get('X-RateLimit-Remaining')
        rate_limit_info['x_ratelimit_reset'] = headers.get('X-RateLimit-Reset')
        rate_limit_info['retry_after'] = headers.get('Retry-After')
        rate_limit_info['content_length'] = headers.get('Content-Length') # Useful for identifying cache hits

        return rate_limit_info

    def test_rate_limiting(self):
        """
        Tests the rate limiting by sending multiple requests and analyzing
        the responses.
        """
        logging.info(f"Starting rate limiting test against {self.url}")
        responses = []
        start_time = time.time()

        for i in range(self.max_requests):
            response = self.send_request()
            if response:
                responses.append(self.analyze_response(response))
                if i % 10 == 0:
                    logging.info(f"Sent {i+1} requests")
            else:
                logging.warning("Request failed, skipping analysis.")
                responses.append(None)

            # Enforce the requests per second limit
            elapsed_time = time.time() - start_time
            sleep_time = (i + 1) / self.requests_per_second - elapsed_time
            if sleep_time > 0:
                time.sleep(sleep_time)

        logging.info("Rate limiting test completed.")
        return responses

    def report_results(self, responses):
        """
        Reports the results of the rate limiting test.

        Args:
            responses (list): A list of dictionaries containing rate limiting
                              information for each response.
        """
        if not responses:
            logging.warning("No responses to report.")
            return

        print("\n--- Rate Limiting Test Results ---")
        blocked_count = 0
        error_count = 0

        for i, result in enumerate(responses):
            print(f"\nRequest #{i+1}:")
            if result is None:
                print("  Request Failed.")
                error_count +=1
                continue

            for key, value in result.items():
                print(f"  {key}: {value}")

            if result['status_code'] in [429, 503]: # Common rate limit error codes
                blocked_count += 1

        print("\n--- Summary ---")
        print(f"Total Requests: {len(responses)}")
        print(f"Blocked Requests (429/503): {blocked_count}")
        print(f"Failed Requests: {error_count}")

        if blocked_count > 0:
            print("\nPossible Rate Limiting Detected.")
        else:
            print("\nNo Rate Limiting Appears to be in Effect.")

def setup_argparse():
    """
    Sets up the argument parser for the command line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="Tests if rate limiting is implemented correctly by sending multiple requests."
    )
    parser.add_argument(
        "url", type=str, help="The URL to test."
    )
    parser.add_argument(
        "-r", "--requests-per-second", type=int, default=10,
        help="Number of requests to send per second (default: 10)."
    )
    parser.add_argument(
        "-m", "--max-requests", type=int, default=50,
        help="Maximum number of requests to send (default: 50)."
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=5,
        help="Timeout for each request in seconds (default: 5)."
    )
    parser.add_argument(
        "-u", "--user-agent", type=str, default=None,
        help="Custom User-Agent string to use."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging."
    )

    return parser

def main():
    """
    Main function to execute the rate limiting test.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG) # Set logging to debug if verbose flag is set

    try:
        # Input validation: check if the URL starts with http/https
        if not args.url.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")

        tester = RateLimitTester(
            args.url,
            args.requests_per_second,
            args.max_requests,
            args.timeout,
            args.user_agent
        )
        responses = tester.test_rate_limiting()
        tester.report_results(responses)

    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Example Usage:
    # python main.py https://example.com
    # python main.py https://example.com -r 20 -m 100 -t 10
    # python main.py https://example.com -u "MyCustomAgent/1.0"
    main()