    Summary:
    Contract 30 eth
    Attacker 5 eth
    To Win: Attack balance == 35 eth

    Answer:
    create a helper contract that will return eth  when requested   5
    send 4 eth to helper contract                                   1

    Use a hash collision to impersonate junior pigeon in `becomeAPigeon()`
    complete task until you have exactly enough points for promotion (task is to spy on other users the amount of eth they determines the amount of points you get
    before promoting flyAway() to withdraw money                    6
    promote and impersonate another pigeon
    complete task until you have exactly enough points for promotion
    before promoting flyAway() to withdraw money                    16
    promote and impersonate another pigeon
    flyAway()                                                       31
    request eth back from helper                                    35

    PitFalls
    - if any eth goes to the owner they wont be able to get it
    - if they go over on their points they wont be able to withdraw for that pigeon
    - only half of the pigeons have eth

    Things they should notice
    - possible hash collision
    - private isn't hidden so they should be able to find the input parameters for each code name
    - there is a missing check in task that allows reuse of the same address for completing task
    - 4 is teh GCF of 8 and 12 so it would be the most efficient way to complete the task.
    - the checks in flyAway and promotion check for > and <. meaning there is small room for  ==
