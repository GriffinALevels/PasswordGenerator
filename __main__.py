from tkinter import *
from tkinter import messagebox
from tkinter import ttk
import random
import re

# Password Rules:
# If len < 8 or len > 24:
#   Display error msg
#   Return to main menu
# Check that the password is only allowed characters:
#   Any alphanumeric characters
#   ! $ % ^ & * ( ) - _ = +
# Initial Point Total is password length
# Award bonus points if:
#   contains at least one uppercase letter (5 pts)
#   contains at least one lowercase letter (5 pts)
#   contains at least one digit (5 pts)
#   contains at least one allowed symbol (5 pts)
#   additional 10 points if all above conditions are met
# Deduct points if:
#   contains only letters (5 pts)
#   contains only digits (5 pts)
#   contains only symbols (5 pts)
#   contains three characters in a row from the QWERTY keyboard

# This class is extended by both GeneratePassword and CheckPassword so that they can access common resources
class PasswordHandler(Frame):
	def __init__(self, container):
		super().__init__(container)

		self.password = StringVar()
		self.allowedCharactersRegEx = "[a-zA-Z0-9!$%^&*()_=+]"

	def evalPassword(self) -> tuple:
		password = self.password.get()

		if len(password) == 0:
			return (0, 0)

		if self.isValid(password):
			score = len(password)

			# Award any earned bonus points
			isUppercase = False
			isLowercase = False
			isNumber = False
			isSymbol = False

			if re.search("[A-Z]", password) != None:
				print("Bonus Points (Uppercase letters): 5pts")
				isUppercase = True
				score += 5

			if re.search("[a-z]", password) != None:
				print("Bonus Points (Lowercase letters): 5pts")
				isLowercase = True
				score += 5

			if re.search("\d", password) != None:
				print("Bonus Points (Digits): 5pts")
				isNumber = True
				score += 5

			if password.count("-") >= 1 or re.search("[!$%^&*()_=+]", password):
				print("Bonus Points (Symbols): 5pts")
				isSymbol = True
				score += 5

			if isUppercase and isLowercase and isNumber and isSymbol:
				print("Bonus Points (All): 5pts")
				score += 10

			# Deduct necessary points
			if password.isalpha():
				score -= 5
				print("Deductions (letters only): 5pts")

			if password.isdigit():
				score -= 5
				print("Deductions (digits only): 5pts")

			if len(re.findall("[!$%^&*()_=+]", password)) == len(password) or password.count("-") == len(password):
				score -= 5
				print("Deductions (symbols only): 5pts")

			qwertyOrder = "qwertyuiopasdfghjklzxcvbnm  "
			threes = 0
			for i in range(len(password) - 2):
				if not password[i].isalpha():
					continue

				currChar = qwertyOrder.index(password[i].lower())

				if password[i + 1] == qwertyOrder[currChar + 1]:
					if password[i + 2] == qwertyOrder[currChar + 2]:
						threes += 1
			score -= threes * 5
			print("Deductions (threes): " + str(threes * 5) + "pts")

			print("Password: " + password)
			print("Score: " + str(score))

			
			if score <= 0:
				return (score, "Weak")
			elif score <= 20:
				return (score, "Medium")
			else:
				return (score, "Strong")

	# Checks that the given password only contains valid characters
	def isValid(self, password: str) -> bool:
		if len(password) < 8 or len(password) > 12:
			messagebox.showinfo("Info", "Password must be between 8 and 12 characters long (inclusive)")
			return False  # Password is too short or long

		if password.count(" ") >= 1:
			# Notify user that given password is invalid
			messagebox.showinfo("Info", "Password cannot contain spaces")
			return False  # password invalid
		
		for i in range(password.count("-")):
			password = password.replace("-", "a")

		results = re.findall(self.allowedCharactersRegEx, password)
		if len(results) == len(password):
			return True
		messagebox.showinfo("Info", "Password cannot contain forbidden symbols. Allowed symbols are: ! $ % ^ & * ( ) - _ = +")
		return False   # Password Invalid


class CheckPassword(PasswordHandler):
	def __init__(self, container):
		self.container = container

		self.scoreLabelContent = StringVar()
		self.passwordRatingContent = StringVar()

		self.scoreLabelContent.set("Score: ")
		self.passwordRatingContent.set("Strength: ")

		super().__init__(container)

		self.title = Label(self, text="Password Evaluator")
		self.entryField = Entry(self, textvariable=self.password)
		self.evaluateBtn = Button(self, text="Evaluate", command=self.updateInfo)
		self.passwordScoreLabel = Label(self, textvariable=self.scoreLabelContent)
		self.passwordRating = Label(self, textvariable=self.passwordRatingContent)
		self.backBtn = Button(self, text="Back", command=self.backToMain)

		self.title.pack(fill=BOTH, expand=True)
		self.entryField.pack(fill=BOTH, expand=True)
		self.evaluateBtn.pack(fill=BOTH, expand=True)
		self.passwordScoreLabel.pack(fill=BOTH, expand=True)
		self.passwordRating.pack(fill=BOTH, expand=True)
		self.backBtn.pack(fill=BOTH, expand=True)

		self.pack()

	def updateInfo(self) -> None:
		(score, strength) = self.evalPassword()

		if score == 0 and strength == 0:
			return
		
		self.scoreLabelContent.set("Score: " + str(score))
		if score <= 0:
			self.passwordRatingContent.set("Strength: Weak")
		elif score <= 20:
			self.passwordRatingContent.set("Strength: Medium")
		else:
			self.passwordRatingContent.set("Strength: Strong")

	def backToMain(self) -> None:
		self.pack_forget()
		self.container.mainMenu.pack()


class GeneratePassword(PasswordHandler):
	def __init__(self, container):
		self.container = container

		super().__init__(container)

		self.passwordLabel = StringVar()

		self.passwordLabel.set("Password: ")
		self.allowedCharacters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 
		'!', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

		self.createdPassword = Label(self, textvariable=self.passwordLabel)
		self.genPasswordBtn = Button(self, text="Generate", command=self.genPassword)
		self.copyPassword = Button(self, text="Copy", command=self.copyPassword)
		self.backBtn = Button(self, text="Back", command=self.backToMain)

		self.createdPassword.pack(fill=BOTH, expand=True)
		self.genPasswordBtn.pack(fill=BOTH, expand=True)
		self.copyPassword.pack(fill=BOTH, expand=True)
		self.backBtn.pack(fill=BOTH, expand=True)

		self.pack()

	def genPassword(self) -> None:
		self.password.set("")

		length = random.randint(8, 12)
		randPassword = ""
		strength = ""
		
		while strength != "Strong":
			for i in range(length):
				randPassword += self.allowedCharacters[random.randint(0, len(self.allowedCharacters) - 1)]
			
			self.password.set(randPassword)
			(score, strength) = self.evalPassword()

		self.passwordLabel.set("Password: " + self.password.get())

	def copyPassword(self) -> None:
		root.clipboard_clear()
		root.clipboard_append(self.password.get())
		root.update()

	def backToMain(self):
		self.pack_forget()
		self.container.mainMenu.pack()


class SaveAccount(PasswordHandler):
	def __init__(self, container):
		self.container = container

		super().__init__(container)

		self.username = StringVar()
		self.passwordRating = StringVar()
		self.passwordStrength = StringVar()

		self.passwordRating.set("Score: ")
		self.passwordStrength.set("Strength: ")

		self.usernameLabel = Label(self, text="Username/Email: ")
		self.passwordLabel = Label(self, text="Password: ")
		self.usernameEntry = Entry(self, textvariable=self.username)
		self.passwordEntry = Entry(self, textvariable=self.password)
		self.passwordRatingLabel = Label(self, textvariable=self.passwordRating)
		self.passwordStrengthLabel = Label(self, textvariable=self.passwordStrength)
		self.saveBtn = Button(self, text="Save Account", command=self.saveBtnClicked)

		self.usernameLabel.grid(row=0, column=0, sticky="NESW")
		self.passwordLabel.grid(row=1, column=0, sticky="NESW")
		self.usernameEntry.grid(row=0, column=1, sticky="NESW")
		self.passwordEntry.grid(row=1, column=1, sticky="NESW")
		self.passwordRatingLabel.grid(row=2, column=0, sticky="NESW")
		self.passwordStrengthLabel.grid(row=2, column=1, sticky="NESW")
		self.saveBtn.grid(row=3, column=0, columnspan=2, sticky="NESW")

		self.pack()

	def saveBtnClicked(self) -> None:
		username = self.username.get()
		password = self.password.get()

		print("Username: " + username)
		print("Password: " + password)

		if username == "":
			messagebox.showinfo("Info", "Please fill in the username field")
			return
		elif password == "":
			messagebox.showinfo("Info", "Please fill in the password field")
			return

		# Check that the username is valid (no spaces)
		if username.count(" ") > 0:
			messagebox.showinfo("Info", "Spaces are not allowed in the username")
			return

		# Evaluate password to display info
		(score, strength) = self.evalPassword()

		if strength != "Strong":
			messageContent = ["Confirmation", "This password is ", ", are you sure you want to use it?"]

			if strength == "Medium":
				messageContent[1] += "only "
				messageContent[2] = " strength" + messageContent[2]

			boxAnswer = messagebox.askyesno(messageContent[0], messageContent[1] + str(strength.lower()) + messageContent[2])

			if boxAnswer == False:
				return

		# Write data to text file


class MainMenu(Frame):
	def __init__(self, container):
		self.container = container

		super().__init__(container)

		self.title = Label(self, text="Password Generator")
		self.checkPasswordButton = Button(self, text="Check Password", command=self.checkPasswordClicked)
		self.generatePasswordButton = Button(self, text="Generate Password", command=self.generatePasswordClicked)
		self.saveAccountButton = Button(self, text="Save Account", command=self.saveAccountClicked)
		self.quitButton = Button(self, text="Quit", command=self.quit)

		self.title.pack(fill=BOTH, expand=True)
		self.checkPasswordButton.pack(fill=BOTH, expand=True)
		self.generatePasswordButton.pack(fill=BOTH, expand=True)
		self.saveAccountButton.pack(fill=BOTH, expand=True)
		self.quitButton.pack(fill=BOTH, expand=True)

		self.pack()

	def checkPasswordClicked(self) -> None:
		self.pack_forget()
		self.container.passEvalFrame = CheckPassword(self.container)

	def generatePasswordClicked(self) -> None:
		self.pack_forget()
		self.container.passGenFrame = GeneratePassword(self.container)

	def saveAccountClicked(self) -> None:
		self.pack_forget()
		self.container.accSaveFrame = SaveAccount(self.container)

	def quit(self):
		global root
		root.destroy()


class Root(Tk):
	def __init__(self):
		super(Root, self).__init__()

		# Configure root window
		self.title("Password Generator/Evaluator")
		self.minsize(350,280)

		self.tk.call("source", "Azure/azure.tcl")
		self.tk.call("set_theme", "dark")

		self.mainMenu = MainMenu(self)
		self.passEvalFrame = None
		self.passGenFrame = None


if __name__ == "__main__":
	root = Root()

	root.mainloop()