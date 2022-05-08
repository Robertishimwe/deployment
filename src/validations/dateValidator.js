export const isBeforeToday = async (departureDate) => {
  const newDate = new Date();
  const CurrentDate = `${newDate.getFullYear()}-${
    newDate.getMonth() + 1
  }-${newDate.getDate()}`;
  if (departureDate >= CurrentDate) {
    return true;
  }
};

export const isBeforeDepartureDate = async (departureDate, returnDate) => {
  if (departureDate <= returnDate) {
    return true;
  }
};