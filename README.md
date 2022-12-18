<h1 align="center" > Threat Profile </h3>

<p align="center"> 

This application is part of the final assessment of Information Security Management as part of PgDip in Computer science at the University of Essex Online. The goal of this application is to create threat profiles according to the OCTAVE-S risk assessment framework.
</p>

## Table of Contents
- [Table of Contents](#table-of-contents)
- [About](#about)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Running the script](#running-the-script)
- [Application instructions](#application-instructions)
  - [Option 1: Receptionist](#option-1-receptionist)
  - [Option 2: Nurse](#option-2-nurse)
  - [Option 3: Doctor](#option-3-doctor)
  - [Option 4: Administration](#option-4-administration)
  - [Option 5: Return to the main menu anywhere in the program](#option-5-return-to-the-main-menu-anywhere-in-the-program)
  - [Option 6: Quit the program from the main menu](#option-6-quit-the-program-from-the-main-menu)
- [Built Using](#built-using)
- [Author](#author)
- [License MIT](#license-mit)

## About

 The application accepts json files that contain threat properties according to the OCTAVE-S framework (). Each json file could contain information about several threats in one scenario. The data that needs to be supplied in the json file contains Asset, Access, Actors, Motives and Outcomes), with Access and Motives being optional, along with probability and impact scores. The software will then generate threat profiles and calculate PI score for each threat profile, in addition to a total PI score for the scenario to allow comparison.


<img src="images/Design.png" width="1000">


Data persistence was managed through csv files.
## Getting Started

The following instructions will guide you on how to run this python script.

### Prerequisites

Python 3 is needed to run this project.

If you don't have python installed on your computer, follow this link to install it [python](https://www.python.org).

You can check if you have python 3 installed by running the following command on the terminal (MacOS) or command prompt (Windows)

```
python --version
```
Example output:

```
Python 3.11.1
```


### Running the script

- Download the project folder [DoctorSurgery](https://github.com/drmohammadatieh/DoctorSurgery/archive/refs/heads/master.zip)

- Open the terminal on MacOS or the command prompt on Windows 7/10.
- Go to the directory that contains the project files. Example:
  
  In MacOS:
  
  ```
  cd  Downloads/DoctorSurgery/
  ```
  In Windows:

   ```
  cd  Downloads\DoctorSurgery\
  ```
- Run the script by typing the following command

  ```
  python main.py
  ```

Main screen will look like this:

<img src="images/main_screen.png" width="1000">

## Application instructions

This program has a user-friendly CLI interface as seen above. To navigate through the application, you just need to type in the selection number, then hit enter key. The main screen is shown above. You have different options to select from.

### Option 1: Receptionist
  
  This menu option will provide receptionist functionalities including registering patients, booking/canceling appointments and forwarding prescription repeat requests.
  <img src="images/Receptionist.png" width="1000">

### Option 2: Nurse
  
  This menu option will provide receptionist nurse functionalities including viewing appointments, writing consultations and viewing consultations.
  <img src="images/Receptionist.png" width="1000">
  
### Option 3: Doctor
  
  This menu option will provide doctor functionalities including viewing appointments, writing consultations and prescriptions, and viewing consultations and prescriptions.
  <img src="images/Doctor.png" width="1000">

### Option 4: Administration

  This menu option will provide administration functionalities including registering doctors and nurses.

### Option 5: Return to the main menu anywhere in the program
  To return to a previous menu, you just need to type -1 followed by enter anywhere in the application.
  <img src="images/main_screen.png" width="1000">

### Option 6: Quit the program from the main menu
  To quit the application completely, you just need to return to the main menu then type 0 followed by enter key.
  <img src="images/main_screen.png" width="1000">
   

## Built Using

- [Python 3.9](https://www.python.org) - Interpreted programming language.

## Author

- [@drmohammadatieh](https://github.com/drmohammadatieh)
  
## License [MIT](https://github.com/drmohammadatieh/Follow-Up-Schedule/blob/master/LICENSE)


