class SeverityEngine:
 """  SOC Risk Score Engine """

  def calculate(self, dataframe):

   dataframe["risk_score"] = dataframe["threat"].apply(
              self._risk_score
                               )
                dataframe["severity"] = dataframe["risk_score"].apply(
                    self._severity
                               )
                        return dataframe
                                 def _risk_score(self, threat):

                                  scores = {
                                 "Credential Dumping": 9.8,

                                 "PowerShell Abuse": 9.4,
                                 "Ransomware Execution": 10.0,
                                 "Lateral Movement": 9.3,
                                 "Persistence": 8.8,
                                 "Privilege Escalation": 9.5,

                                 "Defense Evasion": 8.7,
                                 "Suspicious Login": 7.2,
                                 "Reconnaissance": 5.6

                                 }
         return scores.get(                                                                                                                                                                                                                                     
                  threat,                                                                                                                                                                                                                                          
                   6.5
                )

         def _severity(self, score):
         if score >= 9.0:
                 return "Critical"

         elif score >= 7.0:
                 return "High"

                elif score >= 4.0:
return "Medium"
else:
return "Low"                                                                                                                                                                                                                                                                                       