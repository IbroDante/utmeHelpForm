from app import app, db, Form 
import csv
from datetime import datetime


def import_data(csv_filename):
    with open(csv_filename, 'r') as file:
        reader = csv.DictReader(file)

        with app.app_context():
            for row in reader:
                # Extract relevant data from the CSV row
                centreno = row.get('centreno')
                centrename = row.get('centrename')
                state = row.get('state')
                sessionno = row.get('sessionno', 'Default Session')[:50]
                caller = row.get('caller', 'Default caller')
                issuecat = row.get('issuecat', 'Default issuecat')
                description = row.get('description', 'Default description')
                descriptionprevious = row.get('descriptionprevious', 'Default descriptionprevious')
                solution = row.get('solution', 'Default solution')
                resolved = row.get('resolved', 'Default resolved')
                phonenumber = row.get('phonenumber', 'Default phonenumber')
                transfer_to_user = int(row.get('transfer_to_user', 0))
                date_created = datetime.now()
                date_updated = datetime.now()
                updated_by = row.get('updated_by', 'Default updated_by')
                sender_id = row.get('sender_id')

                print(f"centreno: {centreno}, centrename: {centrename}, state: {state}")

                # Create an instance of the Form model with the extracted data
                form_instance = Form(name="Default Name", centreno=centreno, centrename=centrename, state=state, sessionno=sessionno, caller=caller, issuecat=issuecat,  description=description,  descriptionprevious=descriptionprevious, solution=solution, resolved=resolved, phonenumber=phonenumber, transfer_to_user=transfer_to_user, date_created=date_created,date_updated=date_updated, updated_by=updated_by, sender_id=sender_id)

                # Add the instance to the database session
                db.session.add(form_instance)

            # Commit changes to the database
            db.session.commit()


csv_filename = 'ibro1.csv'
import_data(csv_filename)
