Starts a real ASP.NET Core server with WebFrontAuth already wired, so a test can log in on its first
line.

What is missing is filled in conditionally: a map without a user provider gets a fake database of
five named users, a map without a login service gets a fake one that takes "success" as everyone's
password. An application that brings its own keeps its own.

The fakes are built to be bent - the user list is mutable and the logic is virtual - and helpers
parse both halves of what the server answers: the JSON response with its token and error pair, and
the cookies, with the device and user read out of the long-term one.

CORS is opened to everything, credentials included. Tests only.
