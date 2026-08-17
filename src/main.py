def main():
    print("Phishing Email Detector")
    print("--------------------------")
    print("Paste the email content below: ")

    #For multiline 
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

    detect_keywords(email)

#Step 2 detect suspicious keywords 
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

if __name__ == "__main__":
        main()

