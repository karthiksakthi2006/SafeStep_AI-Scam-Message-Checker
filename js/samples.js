/**
 * SafeStep Curated Sample Messages
 * Contains both realistic suspicious scam messages and benign ordinary messages.
 * Note: All contact names, phone numbers, and URLs are entirely fictional and safe.
 */

const SAMPLE_MESSAGES = {
  suspicious: [
    {
      id: 'suspicious_bank_alert',
      title: '🚨 Bank Account Suspension Alert',
      tag: 'Urgent Phishing',
      snippet: 'URGENT: Your First National Bank account has been restricted...',
      text: 'URGENT: Your First National Bank account has been restricted due to unauthorized login attempts. Immediate action required within 24 hours to prevent permanent closure. Verify your identity now at http://firstnational-security-login.xyz/verify to restore access.'
    },
    {
      id: 'suspicious_otp_theft',
      title: '🔑 Fake Support OTP Harvesting',
      tag: 'Credential Theft',
      snippet: 'Your verification code is 849201. A support agent requires...',
      text: 'Google Security: Your one-time verification code is 849201. An agent is verifying an unrecognized sign-in from Texas. Please reply immediately with the 6-digit code or share your password to cancel this request.'
    },
    {
      id: 'suspicious_lottery_prize',
      title: '🎁 Unsolicited $1,000,000 Lottery Winner',
      tag: 'Prize Bait',
      snippet: 'CONGRATULATIONS! You have won $1,000,000 in the Global Draw...',
      text: 'CONGRATULATIONS! Your mobile number was selected as the lucky winner of a $1,000,000 cash prize and a free iPhone 15 Pro in the 2026 International Sweepstakes. To claim your reward, send a processing fee of $150 via Apple gift card or Bitcoin to our agent.'
    },
    {
      id: 'suspicious_legal_threat',
      title: '⚖️ Law Enforcement / Arrest Threat',
      tag: 'Legal Scare',
      snippet: 'FINAL WARNING: Arrest warrant issued by Federal Tax Bureau...',
      text: 'FINAL NOTICE: An arrest warrant has been issued against you by the Federal Tax Compliance Bureau. Law enforcement officers will arrive at your residence within 2 hours. Call 1-800-555-0144 immediately and pay overdue penalty via Western Union wire transfer to halt legal action.'
    },
    {
      id: 'suspicious_delivery_fee',
      title: '📦 Spoofed Postal Delivery Fee',
      tag: 'Smishing',
      snippet: 'USPS Notice: Your parcel cannot be delivered due to $2.30 fee...',
      text: 'USPS Alert: Your package #US90281 cannot be delivered due to an incorrect address and unpaid customs fee of $2.30. Update your billing info within 12 hours at http://usps-redelivery-portal.club/track or parcel will be returned.'
    }
  ],
  ordinary: [
    {
      id: 'ordinary_doctor_appt',
      title: '🩺 Doctor Appointment Reminder',
      tag: 'Safe Notification',
      snippet: 'Hi Alex, reminder of your appointment with Dr. Taylor...',
      text: 'Hi Alex, this is a reminder from Cedar Grove Family Health of your upcoming appointment with Dr. Taylor tomorrow, Oct 2nd at 10:15 AM. Please reply C to confirm, or call our reception desk at (555) 018-9920 if you need to reschedule.'
    },
    {
      id: 'ordinary_shipping_update',
      title: '📦 E-Commerce Delivery Notice',
      tag: 'Safe Transactional',
      snippet: 'Your EcoStore order #8921 has been delivered to your front porch...',
      text: 'Your EcoStore order #8921 has been delivered to your front porch today. No signature was required. Thank you for shopping with us! If you have any questions, visit our help section in your account.'
    },
    {
      id: 'ordinary_friend_chat',
      title: '💬 Casual Friend Message',
      tag: 'Safe Personal',
      snippet: 'Hey! Are we still on for lunch today around 1:00 PM?...',
      text: 'Hey! Are we still on for lunch today around 1:00 PM at the noodle bar? Let me know if that time still works or if we should push to 1:30.'
    },
    {
      id: 'ordinary_library_notice',
      title: '📚 Community Library Due Date',
      tag: 'Safe Reminder',
      snippet: 'Westside Public Library: The items checked out on card ending in 4102...',
      text: 'Westside Public Library: The 2 books checked out on your card ending in 4102 are due in 3 days on Monday, Oct 5th. You can renew items through your online library account or return them to any book drop.'
    }
  ]
};

// Export for Node.js test environment if needed
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SAMPLE_MESSAGES };
}
