![Screenshot 2023-09-10 at 13 12 53](https://github.com/IbroDante/EduNg/assets/53307395/e8b21c05-0dc3-45b9-a870-d9ae1cc63623)

Project Name:

EduNg - Educational Platform

Introduction:

EduNg is an educational platform designed to facilitate the sharing of knowledge, ideas, and insights within the education community. This platform empowers educators, students, and enthusiasts to create, publish, and explore educational content. Whether you want to write articles on teaching methodologies, share learning resources, or discuss educational trends, EduNg provides the ideal space for collaboration and knowledge sharing.

Deployed Site
Final Project Blog Article
Author(s): Ibrahim Balogun (LinkedIn)
Installation:

To run EduNg locally for development or testing, follow these steps:

Clone the repository:

git clone https://github.com/IbroDante/EduNg
Navigate to the project directory:

cd edung
Create a virtual environment (optional but recommended):

python -m venv venv
Activate the virtual environment:

Windows:

venv\Scripts\activate
Linux/macOS:

source venv/bin/activate
Install the required dependencies:

pip install -r requirements.txt
Set up the database:

flask db init
flask db migrate
flask db upgrade
Start the development server:


flask run
Access EduNg in your web browser at http://localhost:5000.

Usage:

EduNg offers a user-friendly platform for educational content creators and learners. Here are some key features:

User Registration: Create an account to start sharing your knowledge or exploring educational content.

Create and Publish: Authors can create and publish blog posts, articles, and educational materials.

Search and Discover: Users can search for topics of interest, explore content by category, and follow their favorite authors.

Interactive Community: Engage with the educational community by commenting on posts, liking content, and following authors.

Contributing:

We welcome contributions from the open-source community to enhance EduNg. If you'd like to contribute, please follow these guidelines:

Fork the repository on GitHub.

Clone your forked repository to your local machine.

Create a new branch for your feature or bug fix:


git checkout -b feature/your-feature-name
Make your changes, commit them, and push to your fork:


git add .
git commit -m "Your descriptive commit message"
git push origin feature/your-feature-name
Create a Pull Request (PR) to the main branch of the original repository. Please provide a clear description of your changes in the PR.

Your PR will be reviewed, and upon approval, it will be merged into the main project.

Related Projects:

EduNg Frontend - The frontend part of the EduNg platform.
Licensing:

EduNg is released under the NG License.

Feel free to explore EduNg, contribute to its development, and join our educational community!
