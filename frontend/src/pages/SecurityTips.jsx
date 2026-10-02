import { AlertTriangle } from 'lucide-react'

const tips = [
  {
    title: 'Check the domain carefully',
    description: 'Phishing sites often use domains that resemble legitimate websites with slight misspellings or added words. Always verify the domain name before entering any information.',
  },
  {
    title: 'Be cautious with unexpected login links',
    description: 'If you receive an unexpected email or message asking you to log in, navigate to the website directly through your browser rather than clicking the provided link.',
  },
  {
    title: "Verify HTTPS but don't treat it as proof of legitimacy",
    description: 'While HTTPS indicates encrypted communication, phishing sites can also use HTTPS. A padlock icon alone does not guarantee that a website is trustworthy.',
  },
  {
    title: 'Avoid entering credentials into suspicious websites',
    description: 'Never enter passwords, financial information, or personal data on websites that appear unfamiliar or that you reached through unsolicited links.',
  },
  {
    title: 'Check shortened URLs carefully',
    description: 'URL shorteners can hide the actual destination. Use URL preview tools or expand shortened URLs before visiting them, especially if shared through unfamiliar sources.',
  },
  {
    title: 'Be cautious with urgent messages',
    description: 'Phishing attempts often create a sense of urgency with phrases like "Your account will be suspended." Legitimate organizations rarely pressure you with immediate deadlines.',
  },
  {
    title: 'Inspect spelling and unusual domain structures',
    description: 'Look for misspellings, extra hyphens, unusual subdomains, or numeric characters in domain names. These can indicate a phishing attempt.',
  },
  {
    title: 'Use official websites for sensitive services',
    description: 'For banking, email, or other sensitive accounts, always navigate directly to the official website by typing the URL or using a trusted bookmark.',
  },
  {
    title: 'Keep browsers and security software updated',
    description: 'Modern browsers include phishing protection features. Keep your browser and security software up to date to benefit from the latest protections.',
  },
  {
    title: 'Never rely on one indicator alone',
    description: 'No single feature can definitively identify a phishing website. Consider multiple factors including URL structure, content, context, and source before trusting a website.',
  },
]

export default function SecurityTips() {
  return (
    <>
      <div className="page-header">
        <h2>Security Tips</h2>
        <p>Learn how to identify and protect yourself from phishing attempts.</p>
      </div>

      <div className="tips-grid">
        {tips.map((tip, index) => (
          <div className="tip-card" key={index}>
            <div className="tip-number" aria-hidden="true">{index + 1}</div>
            <h4>{tip.title}</h4>
            <p>{tip.description}</p>
          </div>
        ))}
      </div>

      {/* Disclaimer */}
      <div className="disclaimer-card" role="note">
        <AlertTriangle size={24} aria-hidden="true" />
        <p>
          <strong>Disclaimer:</strong> PhishShield AI provides an automated risk assessment based on URL characteristics.
          It does not guarantee that a website is safe or malicious. The model performs static URL feature analysis
          and does not inspect webpage content, execute JavaScript, or perform DNS reputation checks.
          Always exercise caution and use multiple sources of information when evaluating website safety.
        </p>
      </div>
    </>
  )
}
