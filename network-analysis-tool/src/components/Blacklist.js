// Blacklist.js
const Blacklist = ({ blacklist }) => {
  return (
      <div>
          <h3>Blacklisted IPs</h3>
          <ul>
              {blacklist.map(ip => (
                  <li key={ip}>{ip}</li>
              ))}
          </ul>
      </div>
  );
};

export default Blacklist;

