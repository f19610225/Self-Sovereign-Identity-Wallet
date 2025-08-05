(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_NOT_FOUND (err u101))
(define-constant ERR_ALREADY_EXISTS (err u102))
(define-constant ERR_INVALID_CREDENTIAL (err u103))
(define-constant ERR_ACCESS_DENIED (err u104))
(define-constant ERR_EXPIRED (err u105))

(define-constant ERR_INVALID_BACKUP (err u109))
(define-constant ERR_BACKUP_NOT_FOUND (err u110))
(define-constant ERR_BACKUP_EXPIRED (err u111))

(define-data-var min-rating uint u1)
(define-data-var max-rating uint u5)

(define-map user-profiles
  { user: principal }
  {
    created-at: uint,
    is-active: bool,
    credential-count: uint
  }
)

(define-map credentials
  { user: principal, credential-id: (string-ascii 64) }
  {
    credential-type: (string-ascii 32),
    issuer: principal,
    data-hash: (buff 32),
    issued-at: uint,
    expires-at: (optional uint),
    is-verified: bool,
    verification-count: uint
  }
)

(define-map access-permissions
  { owner: principal, requester: principal, credential-id: (string-ascii 64) }
  {
    granted-at: uint,
    expires-at: uint,
    access-level: (string-ascii 16),
    is-active: bool
  }
)

(define-map trusted-issuers
  { issuer: principal }
  {
    name: (string-ascii 64),
    added-at: uint,
    is-active: bool,
    issued-count: uint
  }
)

(define-map verification-requests
  { request-id: uint }
  {
    requester: principal,
    credential-owner: principal,
    credential-id: (string-ascii 64),
    requested-at: uint,
    status: (string-ascii 16),
    response-data: (optional (buff 32))
  }
)

(define-data-var next-request-id uint u1)

(define-public (create-profile)
  (let ((user tx-sender))
    (asserts! (is-none (map-get? user-profiles { user: user })) ERR_ALREADY_EXISTS)
    (map-set user-profiles
      { user: user }
      {
        created-at: stacks-block-height,
        is-active: true,
        credential-count: u0
      }
    )
    (ok true)
  )
)

(define-public (add-credential (credential-id (string-ascii 64)) (credential-type (string-ascii 32)) (issuer principal) (data-hash (buff 32)) (expires-at (optional uint)))
  (let ((user tx-sender))
    (asserts! (is-some (map-get? user-profiles { user: user })) ERR_NOT_FOUND)
    (asserts! (is-none (map-get? credentials { user: user, credential-id: credential-id })) ERR_ALREADY_EXISTS)
    (map-set credentials
      { user: user, credential-id: credential-id }
      {
        credential-type: credential-type,
        issuer: issuer,
        data-hash: data-hash,
        issued-at: stacks-block-height,
        expires-at: expires-at,
        is-verified: false,
        verification-count: u0
      }
    )
    (map-set user-profiles
      { user: user }
      (merge (unwrap-panic (map-get? user-profiles { user: user }))
        { credential-count: (+ (get credential-count (unwrap-panic (map-get? user-profiles { user: user }))) u1) }
      )
    )
    (ok true)
  )
)

(define-public (verify-credential (credential-owner principal) (credential-id (string-ascii 64)))
  (let ((issuer tx-sender)
        (credential (unwrap! (map-get? credentials { user: credential-owner, credential-id: credential-id }) ERR_NOT_FOUND)))
    (asserts! (is-eq (get issuer credential) issuer) ERR_UNAUTHORIZED)
    (map-set credentials
      { user: credential-owner, credential-id: credential-id }
      (merge credential
        {
          is-verified: true,
          verification-count: (+ (get verification-count credential) u1)
        }
      )
    )
    (ok true)
  )
)

(define-public (grant-access (requester principal) (credential-id (string-ascii 64)) (access-level (string-ascii 16)) (duration uint))
  (let ((owner tx-sender))
    (asserts! (is-some (map-get? credentials { user: owner, credential-id: credential-id })) ERR_NOT_FOUND)
    (map-set access-permissions
      { owner: owner, requester: requester, credential-id: credential-id }
      {
        granted-at: stacks-block-height,
        expires-at: (+ stacks-block-height duration),
        access-level: access-level,
        is-active: true
      }
    )
    (ok true)
  )
)

(define-public (revoke-access (requester principal) (credential-id (string-ascii 64)))
  (let ((owner tx-sender))
    (asserts! (is-some (map-get? access-permissions { owner: owner, requester: requester, credential-id: credential-id })) ERR_NOT_FOUND)
    (map-delete access-permissions { owner: owner, requester: requester, credential-id: credential-id })
    (ok true)
  )
)

(define-public (request-verification (credential-owner principal) (credential-id (string-ascii 64)))
  (let ((request-id (var-get next-request-id))
        (requester tx-sender))
    (map-set verification-requests
      { request-id: request-id }
      {
        requester: requester,
        credential-owner: credential-owner,
        credential-id: credential-id,
        requested-at: stacks-block-height,
        status: "pending",
        response-data: none
      }
    )
    (var-set next-request-id (+ request-id u1))
    (ok request-id)
  )
)

(define-public (respond-to-verification (request-id uint) (approve bool) (response-data (optional (buff 32))))
  (let ((request (unwrap! (map-get? verification-requests { request-id: request-id }) ERR_NOT_FOUND)))
    (asserts! (is-eq (get credential-owner request) tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-eq (get status request) "pending") ERR_INVALID_CREDENTIAL)
    (map-set verification-requests
      { request-id: request-id }
      (merge request
        {
          status: (if approve "approved" "denied"),
          response-data: response-data
        }
      )
    )
    (ok true)
  )
)

(define-public (add-trusted-issuer (issuer principal) (name (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (map-set trusted-issuers
      { issuer: issuer }
      {
        name: name,
        added-at: stacks-block-height,
        is-active: true,
        issued-count: u0
      }
    )
    (ok true)
  )
)

(define-public (remove-trusted-issuer (issuer principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (is-some (map-get? trusted-issuers { issuer: issuer })) ERR_NOT_FOUND)
    (map-set trusted-issuers
      { issuer: issuer }
      (merge (unwrap-panic (map-get? trusted-issuers { issuer: issuer }))
        { is-active: false }
      )
    )
    (ok true)
  )
)

(define-read-only (get-user-profile (user principal))
  (map-get? user-profiles { user: user })
)

(define-read-only (get-credential (user principal) (credential-id (string-ascii 64)))
  (map-get? credentials { user: user, credential-id: credential-id })
)

(define-read-only (get-access-permission (owner principal) (requester principal) (credential-id (string-ascii 64)))
  (let ((permission (map-get? access-permissions { owner: owner, requester: requester, credential-id: credential-id })))
    (match permission
      perm (if (and (get is-active perm) (> (get expires-at perm) stacks-block-height))
             (some perm)
             none)
      none
    )
  )
)

(define-read-only (get-verification-request (request-id uint))
  (map-get? verification-requests { request-id: request-id })
)

(define-read-only (get-trusted-issuer (issuer principal))
  (map-get? trusted-issuers { issuer: issuer })
)

(define-read-only (is-credential-accessible (owner principal) (requester principal) (credential-id (string-ascii 64)))
  (let ((permission (get-access-permission owner requester credential-id)))
    (is-some permission)
  )
)

(define-read-only (is-credential-expired (user principal) (credential-id (string-ascii 64)))
  (let ((credential (map-get? credentials { user: user, credential-id: credential-id })))
    (match credential
      cred (match (get expires-at cred)
             exp-time (>= stacks-block-height exp-time)
             false)
      true
    )
  )
)

(define-read-only (get-next-request-id)
  (var-get next-request-id)
)

(define-constant ERR_INVALID_RATING (err u106))
(define-constant ERR_ALREADY_RATED (err u107))
(define-constant ERR_CANNOT_RATE_SELF (err u108))

(define-map issuer-ratings
  { issuer: principal, rater: principal }
  {
    rating: uint,
    comment: (string-ascii 128),
    created-at: uint
  }
)

(define-map issuer-reputation
  { issuer: principal }
  {
    total-ratings: uint,
    rating-sum: uint,
    avg-rating: uint,
    last-updated: uint
  }
)


(define-public (rate-issuer (issuer principal) (rating uint) (comment (string-ascii 128)))
  (let ((rater tx-sender))
    (asserts! (not (is-eq rater issuer)) ERR_CANNOT_RATE_SELF)
    (asserts! (and (>= rating (var-get min-rating)) (<= rating (var-get max-rating))) ERR_INVALID_RATING)
    (asserts! (is-none (map-get? issuer-ratings { issuer: issuer, rater: rater })) ERR_ALREADY_RATED)
    (map-set issuer-ratings
      { issuer: issuer, rater: rater }
      {
        rating: rating,
        comment: comment,
        created-at: stacks-block-height
      }
    )
    (unwrap-panic (update-issuer-reputation issuer rating))
    (ok true)
  )
)

(define-public (update-rating (issuer principal) (new-rating uint) (new-comment (string-ascii 128)))
  (let ((rater tx-sender)
        (old-rating-data (unwrap! (map-get? issuer-ratings { issuer: issuer, rater: rater }) ERR_NOT_FOUND)))
    (asserts! (and (>= new-rating (var-get min-rating)) (<= new-rating (var-get max-rating))) ERR_INVALID_RATING)
    (map-set issuer-ratings
      { issuer: issuer, rater: rater }
      {
        rating: new-rating,
        comment: new-comment,
        created-at: stacks-block-height
      }
    )
    (unwrap-panic (adjust-issuer-reputation issuer (get rating old-rating-data) new-rating))
    (ok true)
  )
)

(define-private (update-issuer-reputation (issuer principal) (rating uint))
  (let ((current-rep (default-to { total-ratings: u0, rating-sum: u0, avg-rating: u0, last-updated: u0 }
                                  (map-get? issuer-reputation { issuer: issuer })))
        (new-total (+ (get total-ratings current-rep) u1))
        (new-sum (+ (get rating-sum current-rep) rating))
        (new-avg (/ new-sum new-total)))
    (map-set issuer-reputation
      { issuer: issuer }
      {
        total-ratings: new-total,
        rating-sum: new-sum,
        avg-rating: new-avg,
        last-updated: stacks-block-height
      }
    )
    (ok true)
  )
)

(define-private (adjust-issuer-reputation (issuer principal) (old-rating uint) (new-rating uint))
  (let ((current-rep (unwrap-panic (map-get? issuer-reputation { issuer: issuer })))
        (adjusted-sum (+ (- (get rating-sum current-rep) old-rating) new-rating))
        (new-avg (/ adjusted-sum (get total-ratings current-rep))))
    (map-set issuer-reputation
      { issuer: issuer }
      (merge current-rep
        {
          rating-sum: adjusted-sum,
          avg-rating: new-avg,
          last-updated: stacks-block-height
        }
      )
    )
    (ok true)
  )
)

(define-read-only (get-issuer-rating (issuer principal) (rater principal))
  (map-get? issuer-ratings { issuer: issuer, rater: rater })
)

(define-read-only (get-issuer-reputation (issuer principal))
  (map-get? issuer-reputation { issuer: issuer })
)

(define-read-only (get-issuer-avg-rating (issuer principal))
  (match (map-get? issuer-reputation { issuer: issuer })
    rep (some (get avg-rating rep))
    none
  )
)


(define-map credential-backups
  { user: principal, backup-id: uint }
  {
    backup-hash: (buff 32),
    credential-ids: (list 10 (string-ascii 64)),
    created-at: uint,
    expires-at: uint,
    recovery-phrase: (buff 32),
    is-used: bool
  }
)

(define-data-var next-backup-id uint u1)

(define-public (create-backup (credential-ids (list 10 (string-ascii 64))) (recovery-phrase (buff 32)) (duration uint))
  (let ((user tx-sender)
        (backup-id (var-get next-backup-id)))
    (asserts! (is-some (map-get? user-profiles { user: user })) ERR_NOT_FOUND)
    (asserts! (> (len credential-ids) u0) ERR_INVALID_BACKUP)
    (map-set credential-backups
      { user: user, backup-id: backup-id }
      {
        backup-hash: (sha256 recovery-phrase),
        credential-ids: credential-ids,
        created-at: stacks-block-height,
        expires-at: (+ stacks-block-height duration),
        recovery-phrase: recovery-phrase,
        is-used: false
      }
    )
    (var-set next-backup-id (+ backup-id u1))
    (ok backup-id)
  )
)

(define-public (recover-credentials (backup-id uint) (recovery-phrase (buff 32)))
  (let ((user tx-sender)
        (backup (unwrap! (map-get? credential-backups { user: user, backup-id: backup-id }) ERR_BACKUP_NOT_FOUND))
        (verification-hash (sha256 recovery-phrase)))
    (asserts! (> (get expires-at backup) stacks-block-height) ERR_BACKUP_EXPIRED)
    (asserts! (not (get is-used backup)) ERR_BACKUP_NOT_FOUND)
    (asserts! (is-eq (get backup-hash backup) verification-hash) ERR_INVALID_BACKUP)
    (map-set credential-backups
      { user: user, backup-id: backup-id }
      (merge backup { is-used: true })
    )
    (ok (get credential-ids backup))
  )
)

(define-public (extend-backup (backup-id uint) (additional-duration uint))
  (let ((user tx-sender)
        (backup (unwrap! (map-get? credential-backups { user: user, backup-id: backup-id }) ERR_BACKUP_NOT_FOUND)))
    (asserts! (> (get expires-at backup) stacks-block-height) ERR_BACKUP_EXPIRED)
    (asserts! (not (get is-used backup)) ERR_BACKUP_NOT_FOUND)
    (map-set credential-backups
      { user: user, backup-id: backup-id }
      (merge backup { expires-at: (+ (get expires-at backup) additional-duration) })
    )
    (ok true)
  )
)

(define-read-only (get-backup (user principal) (backup-id uint))
  (map-get? credential-backups { user: user, backup-id: backup-id })
)

(define-read-only (is-backup-valid (user principal) (backup-id uint))
  (match (map-get? credential-backups { user: user, backup-id: backup-id })
    backup (and (> (get expires-at backup) stacks-block-height) (not (get is-used backup)))
    false
  )
)