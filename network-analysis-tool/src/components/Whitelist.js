// Whitelist.js
const Whitelist = ({ whitelist }) => {
  return (
      <div>
          <h3>Whitelisted IPs</h3>
          <ul>
              {whitelist.map(ip => (
                  <li key={ip}>{ip}</li>
              ))}
          </ul>
      </div>
  );
};

export default Whitelist;
