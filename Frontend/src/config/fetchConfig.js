const BASE_URL = process.env.REACT_APP_API_BASE_URL;
//private back

const fetchInstance = async (url, options = {}) => {
  const response = await fetch(`${BASE_URL}${url}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.message || 'Something went wrong!');
  }

  return response.json();
};

export const get = (url, options = {}) => fetchInstance(url, { method: 'GET', ...options });

export const post = (url, data, options = {}) =>
  fetchInstance(url, {
    method: 'POST',
    body: JSON.stringify(data),
    ...options,
  });

export const put = (url, data, options = {}) =>
  fetchInstance(url, {
    method: 'PUT',
    body: JSON.stringify(data),
    ...options,
  });

export const del = (url, options = {}) => fetchInstance(url, { method: 'DELETE', ...options });
