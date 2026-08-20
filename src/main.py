import re 
import ipaddress


def main():
    print("Phishing Email Detector")
    print("--------------------------")
    print("Paste the email content below: ")

    #For processing multiline email 
    lines = []
    while True:
        line = input()
        if line:
            lines.append(line)
        else:
            break
    email = "\n".join(lines)

    print("Email received:")
    print(email)

    #step 2
    keyword_score = detect_keywords(email)

    #step 3
    url_score = detect_urls(email)

    #step 4
    sender_score = check_sender_characteristics(email)

    #step 5
    total_score = keyword_score + url_score + sender_score

    if total_score >= 9:
     risk_level = "High"
    elif total_score >= 3:
     risk_level = "Medium"
    else:
     risk_level = "Low"

    print(f"Total Phishing Risk Score: {total_score}")
    print(f"Overall Risk Level: {risk_level}")

#Step 2: Detect suspicious keywords 
def detect_keywords(email):
        #List of common phishing keywords
        suspicious_keywords = ["urgent",
                               "immediately",
                               "action required",
                               "verify your account",
                               "confirm your account",
                               "account suspended",
                               "click here",
                               "reset your password",
                               "unusual activity",
                               "payment required"]
        email_lower = email.lower()
        found_keywords = []

        #Iterate through the keywords 
        for keyword in suspicious_keywords:
            if keyword in email_lower:
                found_keywords.append(keyword)

        #Claculate and display risk score 
        print("Phishing Risk Score:", len(found_keywords))

        #Length wise conditions 
        if len(found_keywords) == 1:
                        print(f"Email contains a suspicious keyword")
        elif len(found_keywords) > 1 and len(found_keywords) < 4:
                        print(f"Email contains multiple suspicious keywords")
        elif len(found_keywords) >= 4:
                        print(f"URGENT! This email has a high phishing risk." + "\n" + "Please be cautious and do not click on any links or download any attachments from this email.")

        #Returns all the suspicious words
        if found_keywords:
             print(f"Found:")
             for keyword in found_keywords:
                  print(keyword)
        else:
             print("No suspicious keyword detected")

        return len(found_keywords)

#Step 3: Detect suspicious links
def detect_urls(email):

       #Extract URLs using regex
       url_pattern = r'(?:https://|http://)?(?:[a-zA-Z0-9]+\.)+(?:[a-zA-Z0-9]+)(?:/[\w.-]*)*'
       urls = re.findall(url_pattern, email)
      

       print("URLs found:")

       total_url_score = 0
       for url in urls:
            print(url)
            total_url_score += analyse_url(url)

       return total_url_score

def analyse_url(url):
    risk_score = 0

    #check if URL contains an IP adress
    try:
        #Check if the URL is valid
        if "//" in url:
            hostname = url.split("//")[1].split("/")[0]
        else:
            hostname = url.split("/")[0]

        ipaddress.ip_address(hostname)
        print(f"URL {url} is a valid IP address.")

        risk_score += 3

    except ValueError:
        print(f"URL uses a domain name.")

    #Check if URL uses HTTPS
    if url.startswith("http://"):
       risk_score += 2

    #Risk score evaluation
    if risk_score >= 5:
        risk_level = "High"
    elif risk_score >= 3:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    print(f"Risk Score: {risk_score}")
    print(f"Risk Level: {risk_level}")

    return risk_score

#STEP 4: Check sender characteritics 
def check_sender_characteristics(email):
      #Extract sender email address using regex
      sender_regex = r"[Ff]rom:.*?([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})"

      match = re.search(sender_regex, email)

      #Calculate score 
      score = 0 
      
      if match:
            sender_email = match.group(1)
            print(f"Sender Email: {sender_email}")

            domain = sender_email.split("@")[1]
            print(f"Sender Domain: {domain}")

            #Check if sender uses a free email provider
            free_email_providers = [
                  "gmail.com",
                  "yahoo.com",
                  "outlook.com",
                  "hotmail.com"
            ]
            

            if domain in free_email_providers:
             score += 2
             print("Warning: Sender uses a free email provider.")

            #Check if sender domain is suspicious
            suspicious_domain_words = [
                  "secure",
                  "verify",
                  "login",
                  "account"
            ]

            found_words = []

            #Check for suspicious words in the domain
            for word in suspicious_domain_words:
                  if word in domain.lower():
                        found_words.append(word)
                        score += 2

            #Returns all the suspicious words
            if found_words:
                print(f"Found:")
                for word in found_words:
                    print(word)
            else:
                print("No suspicious word detected")

            print(f"Sender Risk Score: {score}")
            return score
      else:
            print("No sender email address found.")
            print(f"Sender Risk Score: {score}")
            return score
                  


if __name__ == "__main__":
        main()

