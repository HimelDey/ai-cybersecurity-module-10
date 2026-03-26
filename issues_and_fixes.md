# XSS Vulnerability
In view_archieve.html I have found problematic code as follows

{{ archive.notes|safe }}

{{ archive.content|safe }}

Which creates vulnerability problem

I have used <script>alert('I am compromised')</script> this code in the add archieves text box and it was working

# FIX
I am going to remove the safe tag from the notes to solve this problem