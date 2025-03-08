document.addEventListener('DOMContentLoaded', () => {
    const friendsListContainer = document.getElementById('friends-list');

    const fetchFriends = async () => {
        // **Important:** Replace with the actual way you store and retrieve the authCookie
        const authCookie = getAuthCookie(); // Example: Implement this function
        if(!authCookie){
            console.error("Could not get Auth Cookie");
            return;
        }

        try {
            const response = await fetch('https://api.vrchat.cloud/api/1/auth/user/friends?offline=true', {
                method: 'GET',
                headers: {
                    'Cookie': `auth=${authCookie}` // Set auth cookie in request
                }
            });

            if (!response.ok) {
                throw new Error(`API request failed with status: ${response.status}`);
            }

            const friendsData = await response.json();

            if (friendsData.length === 0) {
                friendsListContainer.innerHTML = '<p>No friends found.</p>';
                return;
            }

            friendsData.forEach(friend => {
                const friendElement = document.createElement('div');
                friendElement.classList.add('friend-item');

                const avatarThumbnail = document.createElement('img');
                avatarThumbnail.src = friend.currentAvatarThumbnailImageUrl;
                avatarThumbnail.alt = `${friend.displayName}'s Avatar`;

                const displayName = document.createElement('p');
                displayName.textContent = friend.displayName;

                const status = document.createElement('p');
                status.textContent = `Status: ${friend.status}`;

                const location = document.createElement('p');
                location.textContent = `Location: ${friend.location}`;

                friendElement.appendChild(avatarThumbnail);
                friendElement.appendChild(displayName);
                friendElement.appendChild(status);
                friendElement.appendChild(location);
                friendsListContainer.appendChild(friendElement);
            });

        } catch (error) {
            console.error('Error fetching or displaying friends:', error);
            friendsListContainer.innerHTML = '<p>Error loading friends. Please try again later.</p>';
        }
    };

    // Helper function (replace with your actual logic to get the cookie)
    function getAuthCookie() {
        // Example: Retrieve the cookie from local storage, if needed
        const cookies = document.cookie.split('; ');
        for (const cookie of cookies) {
            const [name, value] = cookie.split('=');
            if (name === 'auth') {
                return value;
            }
        }
        return null;
    }

    fetchFriends();
});
