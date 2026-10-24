/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, OnInit, ChangeDetectionStrategy } from '@angular/core'
import { jwtDecode } from 'jwt-decode'
import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'

@Component({
  changeDetection: ChangeDetectionStrategy.Eager,
  selector: 'app-last-login-ip',
  templateUrl: './last-login-ip.component.html',
  styleUrls: ['./last-login-ip.component.scss'],
  imports: [MatCardModule, TranslateModule]
})

export class LastLoginIpComponent implements OnInit {
  lastLoginIp: string = '?'

  ngOnInit (): void {
    try {
      this.parseAuthToken()
    } catch (err) {
      console.log(err)
    }
  }

  parseAuthToken () {
    let payload = {} as any
    const token = localStorage.getItem('token')
    if (token) {
      payload = jwtDecode(token)
      if (payload.data.lastLoginIp) {
        // FIX XSS (OWASP A03): se asigna el valor como texto plano; Angular lo escapa al renderizar.
        // Ya no se usa bypassSecurityTrustHtml, que desactivaba la sanitización.
        this.lastLoginIp = payload.data.lastLoginIp
      }
    }
  }
}
