# CodePulse: Web Application Security Demonstrator

## Introduction
CodePulse is an educational tool designed to help users understand web application vulnerabilities, including Cross-Site Scripting (XSS), SQL Injection, and Cross-Site Request Forgery (CSRF). It features a practical, interactive platform where users can not only learn about these vulnerabilities but also test them in a controlled environment.

## Technologies Used
- Django: A high-level web framework for Python which encourages efficient development and simple, intuitive design.
- JavaScript: Used to create interactive interfaces using client-side scripting.
- HTML/CSS: The web application was designed and structured using markup and style languages.

## Main Features
- **User Authentication**: Supports both two-factor and standard authentication procedures, improving the application's safety features.
- **Scanner Functionality**: Contains resources for identifying and reporting possible SQL injection and XSS vulnerabilities in user-provided code snippets and URLs.
- **Educational Content**: Dedicated pages for XSS, SQL injection, and CSRF that not only describe these vulnerabilities but also demonstrate them and discuss mitigation strategies.

## Screenshots
![Home](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/32d058ea-4e06-436e-85da-bfa5b719dfb9)

- This is the CodePulse Home Page, the first page the users interacts with. 
  
![Reg](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/1715654b-da47-4340-bc72-6cdbd7a5d0fb)

- User must enter valid email, and fill in their credentials in order to create and activate an account with CodePulse.

![login](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/f50d2bf3-18be-494c-9a23-e6075dfe7313)

- If user has an existing account, then use credentials of that account, must be valid. 

![Scanner](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/43f6290c-5ebd-4e2f-a30d-aee2311adcd4)

- Users can enter their code snippers into this form and with the vulnerability detected, the user should be able to see a reported message of the vulnerability detect. 
  
![scanner-url](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/5e252b6f-aef8-42f2-bf4c-6d3c33d94bcc)

- Users can add in their URLs for their existing project, but needs to be runninh locally to detect the vulnerability otherwise error. 



## Installation and Setup
To get CodePulse running locally:
```bash
git clone https://github.com/DjenaSiabdellah/CodePulse.git
cd CodePulse
pip install -r requirements.txt
python manage.py runserver
