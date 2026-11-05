# Fake interview assignment (harmless test fixture)

Imitates the behaviour of "Contagious Interview" style repos so `vswarm try` can be tested against it.
It only touches documentation addresses (203.0.113.0/24, example.net), sends no file contents anywhere,
and every action it attempts is something the vswarm sandbox must block or record. Do not run it outside the sandbox
anyway: that is the point of the exercise.
