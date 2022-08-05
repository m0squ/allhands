import datetime

#Get a date with weekdays and months wrote by word
def get_date(text, data="today"):
    if data == "today":
        data = datetime.date.today()
    Weekday = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
    weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    Month = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
    month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    result = text
    try:
        result = result.replace("%W", str(Weekday[data.weekday() + 1]))
        result = result.replace("%w", str(weekday[data.weekday() + 1]))
    except IndexError:
        result = result.replace("%W", str(Weekday[0]))
        result = result.replace("%w", str(weekday[0]))
    result = result.replace("%D", str(data.day))
    try:
        result = result.replace("%M", str(Month[data.month - 1]))
        result = result.replace("%m", str(month[data.month - 1]))
    except IndexError:
        result = result.replace("%M", str(Month[0]))
        result = result.replace("%m", str(month[0]))
    result = result.replace("%Y", str(data.year))
    return result
