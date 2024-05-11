# CodePulse: Web Application Description 

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

![About](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/ba346ac0-8d65-4e07-9dfa-774464994cb7)

- For more Information about CodePulse.
  
![Reg](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/1715654b-da47-4340-bc72-6cdbd7a5d0fb)

- User must enter valid email, and fill in their credentials in order to create and activate an account with CodePulse.

![Verify](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/7071d7e7-7089-453a-b241-b0f730a86dd4)

- Users must enter the code sent to their email to verify their email, resulting in a successful login.

![Welcome](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/d1ea42b2-712a-476d-a064-308e03c678c4)

- Welcome users after registration with successful verified email.

![login](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/f50d2bf3-18be-494c-9a23-e6075dfe7313)

- If user has an existing account, then use credentials of that account, must be valid. 

![Scanner](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/43f6290c-5ebd-4e2f-a30d-aee2311adcd4)

- Users can enter their code snippers into this form and with the vulnerability detected, the user should be able to see a reported message of the vulnerability detect. 
  
![scanner-url](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/5e252b6f-aef8-42f2-bf4c-6d3c33d94bcc)

- Users can add in their URLs for their existing project, but needs to be runninh locally to detect the vulnerability otherwise error. 


![XSS](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/2482c085-ab82-49fe-9b77-fca51684f036)
![SQL](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/4aa59956-6bd7-48e6-a8e3-19815d811c58)
![CSRF](https://github.com/DjenaSiabdellah/CodePulse/assets/73534772/a35aa65e-dacb-42cf-ac1c-e1213605cac5)

- Educational Content for users, and more Resources.




## Installation and Setup
To get CodePulse running locally:
```bash
git clone https://github.com/DjenaSiabdellah/CodePulse.git
cd CodePulse
pip install -r requirements.txt
python manage.py runserver
