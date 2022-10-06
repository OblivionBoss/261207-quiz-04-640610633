import { checkToken } from "../../backendLibs/checkToken";
import { readUsersDB } from "../../backendLibs/dbLib";
export default function summaryRoute(req, res) {
  let adminCount = 0;
  let userCount = 0;
  let totalMoney = 0;
  if (req.method === "GET") {
    //check authentication
    const user = checkToken(req);
    console.log(user);
    if (!user.isAdmin)
      return res.status(403).json({ ok: false, message: "Permission denied" });
    //return res.status(403).json({ ok: false, message: "Permission denied" });
    //compute DB summary
    const users = readUsersDB();
    users.map((user) => {
      if (user.isAdmin) {
        adminCount++;
      } else {
        userCount++;
        totalMoney += user.money;
      }
    });
    return res.status(200).json({
      ok: true,
      userCount: userCount,
      adminCount: adminCount,
      totalMoney: totalMoney,
    });
    //return response
  } else {
    return res.status(400).json({ ok: false, message: "Invalid HTTP Method" });
  }
}
