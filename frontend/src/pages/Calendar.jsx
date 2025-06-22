import React, { useEffect, useState } from 'react';
import moment from 'moment-timezone';
import axios from 'axios';
import { CircularProgress, Box } from '@mui/material';
import '../styles/Calendar.css';


const Calendar = () => {
    const [currentDate, setCurrentDate] = useState(moment());
    const [contests, setContests] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedDate, setSelectedDate] = useState(moment().format('YYYY-MM-DD'));

    useEffect(() => {
        const fetchContests = async () => {
            try {
                const { data } = await axios.get("https://api.digitomize.com/contests");
                setContests(data.results);
                setLoading(false);
            } catch (err) {
                setError(err.message);
                setLoading(false);
            }
        };

        fetchContests();
    }, []);

    const startOfMonth = currentDate.clone().startOf('month');
    const endOfMonth = currentDate.clone().endOf('month');
    const startDate = startOfMonth.clone().startOf('week');
    const endDate = endOfMonth.clone().endOf('week');

    const days = [];
    let day = startDate.clone();

    while (day.isBefore(endDate, 'day')) {
        days.push(day.clone());
        day.add(1, 'day');
    }

    const nextMonth = () => {
        setCurrentDate(currentDate.clone().add(1, 'month'));
    };

    const prevMonth = () => {
        setCurrentDate(currentDate.clone().subtract(1, 'month'));
    };

    const getContestsForDate = (date) => {
        return contests.filter(contest => {
            const contestDate = moment.unix(contest.startTimeUnix).format('YYYY-MM-DD');
            return contestDate === date.format('YYYY-MM-DD');
        });
    };

    const handleDateClick = (date) => {
        setSelectedDate(date.format('YYYY-MM-DD'));
    };

    const generateTimeAndDateURL = (startTimeUnix) => {
        const utcDateAndTime = moment.tz(startTimeUnix * 1000, "UTC");
        const utcStartMonth = utcDateAndTime.format("MM");
        const utcStartDate = utcDateAndTime.format("DD");
        const utcStartYear = utcDateAndTime.format("YYYY");
        const utcStartTime = utcDateAndTime.format("HH:mm:ss");
        const utcStartHour = utcStartTime.split(":")[0];
        const utcStartMin = utcStartTime.split(":")[1];
        const utcStartSec = utcStartTime.split(":")[2];

        const timeAndDateURL = new URL("https://timeanddate.com/worldclock/fixedtime.html");
        const params = {
            day: utcStartDate,
            month: utcStartMonth,
            year: utcStartYear,
            hour: utcStartHour,
            min: utcStartMin,
            sec: utcStartSec,
            p1: 1440, // UTC
        };

        timeAndDateURL.search = new URLSearchParams(params).toString();
        return timeAndDateURL.href;
    };

    if (loading) {
        return (
            <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh" bgcolor="black">
                <CircularProgress />
            </Box>
        );
    }

    if (error) {
        return (
            <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh" bgcolor="black">
                <div className="error-message">Error: {error}</div>
            </Box>
        );
    }

    return (
        <>
            <div className="calendar-container">
                <div className="calendar-wrapper">
                    <div className="calendar-section">
                        <div className="calendar-header">
                            <div className="navigation">
                                <button className="nav-button" onClick={prevMonth}>&lt;</button>
                                <h2 className="month-year">{currentDate.format('MMMM YYYY')}</h2>
                                <button className="nav-button" onClick={nextMonth}>&gt;</button>
                            </div>
                        </div>

                        <div className="calendar-grid">
                            <div className="days-header">
                                {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(day => (
                                    <div key={day} className="day-header">{day}</div>
                                ))}
                            </div>

                            <div className="days-grid">
                                {days.map((day, idx) => {
                                    const isCurrentMonth = day.isSame(currentDate, 'month');
                                    const isToday = day.isSame(moment(), 'day');
                                    const dateKey = day.format('YYYY-MM-DD');
                                    const dateContests = getContestsForDate(day);
                                    const hasContests = dateContests.length > 0;

                                    return (
                                        <div
                                            key={idx}
                                            className={`calendar-day ${!isCurrentMonth ? 'empty' : ''} ${hasContests ? 'has-contest' : ''} ${dateKey === selectedDate ? 'selected' : ''}`}
                                            onClick={() => isCurrentMonth && handleDateClick(day)}
                                        >
                                            <span className="day-number">{day.format('D')}</span>
                                            {isToday && <div className="today-marker"></div>}
                                            {hasContests && (
                                                <div className="contest-indicator">
                                                    <span className="contest-count">{dateContests.length}</span>
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>

                    <div className="contests-sidebar">
                        <div className="contests-section">
                            <h3>Contests on {moment(selectedDate).format('MMMM D, YYYY')}</h3>
                            <div className="contests-list">
                                {getContestsForDate(moment(selectedDate)).length > 0 ? (
                                    getContestsForDate(moment(selectedDate)).map((contest, idx) => {
                                        const startTime = moment.unix(contest.startTimeUnix).format('h:mm A');
                                        const endTime = moment.unix(contest.startTimeUnix + contest.duration * 60).format('h:mm A');
                                        const durationHours = Math.floor(contest.duration / 60);
                                        const durationMinutes = contest.duration % 60;
                                        const timeAndDateURL = generateTimeAndDateURL(contest.startTimeUnix);

                                        return (
                                            <div key={idx} className="contest-item">
                                                <h4>
                                                    <span className="platform-badge">{contest.host}</span>
                                                    {contest.name}
                                                </h4>
                                                <p>
                                                    <span className="label">Time:</span> {startTime} - {endTime} ({durationHours}h {durationMinutes > 0 ? `${durationMinutes}m` : ''})
                                                </p>
                                                <a
                                                    href={contest.url + "?ref=digitomize&utm_source=digitomize"}
                                                    className="contest-link"
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                >
                                                    Join Contest
                                                </a>
                                                
                                            </div>
                                        );
                                    })
                                ) : (
                                    <div className="no-contests">No contests scheduled for this day</div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
};

export default Calendar;
